/*
* Copyright (c) 2026 WinMagic Corp.
* This file is part of the WinMagic LIT reference project.
* This software is dual-licensed:
* 
* 1. GNU Affero General Public License v3.0 (AGPL-3.0)
* 2. Commercial license available from WinMagic Corp.
* 
* You may use this file under the terms of the AGPL-3.0 license
* included in the LICENSE file in the root of this repository.
* 
* For commercial licensing options, OEM redistribution rights,
* proprietary use, or support agreements, please contact WinMagic.
*/

using LIT.ServerMVC.Commons;
using LIT.ServerMVC.Data;
using LIT.ServerMVC.Data.Models;
using Microsoft.EntityFrameworkCore;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace LIT.ServerMVC.Services.Implementation
{
    public class ClientCertificateAuthenticator(ApplicationDbContext dbContext, 
        ICertificateValidationService certificateValidationService, 
        ILogger<ClientCertificateAuthenticator> logger) : IClientCertificateAuthenticator
    {
        public async Task<ClaimsPrincipal?> AuthenticateAsync(X509Certificate2 certificate, string authenticationType, IPAddress? ipAddress)
        {
            try
            {
                var (user, device) = await ValidateCertificateAsync(certificate);
                logger.LogInformation($"User: {user.UserName}, UserId: {user.UserId}, Device: {device.DeviceName} has authenticated using certificate. IP Address: {ipAddress}");

                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, user.UserId.ToString()),
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(Constants.DeviceNameClaim, device.DeviceName)
                };

                return new ClaimsPrincipal(new ClaimsIdentity(claims, authenticationType));
            }
            catch (CertificateLoginException ex)
            {
                logger.LogInformation(ex, $"Attempt to authenticate using certificate failed. IP Address: {ipAddress}");
                return null;
            }
        }

        private async Task<(User user, Device device)> ValidateCertificateAsync(X509Certificate2 certificate)
        {
            var certSubject = new Certificate();
            try
            {
                certSubject = certificateValidationService.GetCertificateSubject(certificate);
            }
            catch (Exception ex)
            {
                throw new CertificateLoginException("Error getting certificate subject", ex);
            }

            try
            {
                var IsUserGuidValid = Guid.TryParse(certSubject.UserIndex, out var userGuid);
                var IsDeviceGuidValid = Guid.TryParse(certSubject.DeviceIndex, out var deviceGuid);
                if (!IsUserGuidValid || !IsDeviceGuidValid)
                    throw new CertificateLoginException("Invalid Guids on certificate subject field");


                var user = await dbContext.Users.FirstOrDefaultAsync(u => u.UserId == userGuid);
                var device = await dbContext.Devices.FirstOrDefaultAsync(d => d.DeviceId == deviceGuid);
                if (user == null || device == null)
                    throw new CertificateLoginException("User or Device does not exist");

                var key = await dbContext.KeyRegistrations
                    .Where(k => k.UserId == userGuid && k.DeviceId == deviceGuid && k.KeyUsage == certSubject.Provider)
                    .OrderByDescending(k => k.DateCreated)
                    .FirstOrDefaultAsync();

                if (key == null)
                    throw new CertificateLoginException("Certificate registration does not exist");


                using var certEccKey = certificate.GetECDsaPublicKey();
                if (certEccKey == null)
                    throw new CertificateLoginException("Only ECC client certificates are currently supported");

                var IsKeyRegistered = CompareECCKeys(certEccKey, key.PublicKey);
                if (!IsKeyRegistered)
                    throw new CertificateLoginException("Certificate public key not registered");

                var serverCACert = dbContext.ServerCerts.FirstOrDefault(sc => sc.Name == Constants.ServerCAName);
                if (serverCACert == null)
                    throw new CertificateLoginException("Server CA is not ready");

                var caCert = new X509Certificate2(serverCACert.Value);
                if (!certificateValidationService.ValidateClientCertificateX509Chain(certificate, caCert)
                    || !certificateValidationService.ValidateClientCertificateChain(certificate, caCert))
                    throw new CertificateLoginException("Certificate failed validation");

                return (user, device);
            }
            catch (Exception ex) when (ex is not CertificateLoginException)
            {
                throw new CertificateLoginException("Certificate login failed. An unexpected error has occurred", ex);
            }
        }

        private bool CompareECCKeys(ECDsa clientCertKey, byte[] registeredKey)
        {
            //client cert
            var certEccKeyParams = clientCertKey.ExportParameters(false);
            var certX = certEccKeyParams.Q.X;
            var certY = certEccKeyParams.Q.Y;
            if (certX == null || certY == null)
                return false;
            var cbKey = BitConverter.ToInt32(registeredKey, 4);
            var format = Encoding.ASCII.GetString(registeredKey, 0, 4);
            var keyX = new ArraySegment<byte>(registeredKey, 8, cbKey).ToArray();
            var keyY = new ArraySegment<byte>(registeredKey, 8 + cbKey, cbKey).ToArray();
            return (keyX.SequenceEqual(certX) && keyY.SequenceEqual(certY));
        }

        private sealed class CertificateLoginException(string message, Exception? innerException = null) : Exception(message, innerException);
    }
}
