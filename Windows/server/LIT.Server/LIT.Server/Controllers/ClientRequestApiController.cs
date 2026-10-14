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

using LIT.ServerMVC.Data.Dtos;
using LIT.ServerMVC.Data.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography.X509Certificates;
using LIT.ServerMVC.Commons;
using LIT.ServerMVC.Data;
using LIT.ServerMVC.Services;
using LIT.ServerMVC.Services.Implementation;
using static LIT.ServerMVC.Data.Models.Certificate;

namespace LIT.ServerMVC.Controllers
{
    [ApiController]
    [Route("api/v1/ClientRequest")]
    public class ClientRequestApiController(ApplicationDbContext dbContext, ICertificateGenerationService certificateGenerationService, ILogger<ClientRequestApiController> logger) : ControllerBase
    {
        [HttpPost]
        public async Task<ClientRequestResponseDto> DoClientRequests(ClientRequestDto model, CancellationToken cancellationToken)
        {
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            logger.LogInformation($"API Request has been made by IP Address: {ipAddress}");
            try
            {
                if (model?.Request == Constants.RegisterKey)
                {
                    logger.LogInformation($"Request Type: {Constants.RegisterKey}, Username: {model?.Username}, IP Address: {ipAddress}");
                    if (String.IsNullOrEmpty(model.DeviceName) || String.IsNullOrEmpty(model.Username) || String.IsNullOrEmpty(model.PubKey) || String.IsNullOrEmpty(model.KeyUsage))
                        throw new Exception();

                    var password = String.IsNullOrEmpty(model.Password) ? model.Username : model.Password;
                    var hashedPassword = Utils.HashPassword(password);

                    await using var transaction = await dbContext.Database.BeginTransactionAsync(cancellationToken);

                    var pubKey = Convert.FromBase64String(model.PubKey);
                    var keyRegistration = await dbContext.KeyRegistrations.Include(k => k.User)
                        .Include(k => k.Device)
                        .FirstOrDefaultAsync(k => k.PublicKey == pubKey, cancellationToken);

                    var isNewKey = keyRegistration == null;

                    if (keyRegistration != null)
                    {
                        keyRegistration.User.UserName = model.Username;
                        keyRegistration.Device.DeviceName = model.DeviceName;
                    }
                    else
                    {
                        var user = new User
                        {
                            UserId = Guid.NewGuid(),
                            UserName = model.Username,
                            Password = hashedPassword
                        };

                        var device = new Device
                        {
                            DeviceId = Guid.NewGuid(),
                            DeviceName = model.DeviceName
                        };

                        keyRegistration = new KeyRegistration
                        {
                            UserId = user.UserId,
                            DeviceId = device.DeviceId,
                            PublicKey = pubKey,
                            KeyType = model.KeyType ?? 0,
                            KeyUsage = model.KeyUsage
                        };

                        dbContext.Users.Add(user);
                        dbContext.Devices.Add(device);
                        dbContext.KeyRegistrations.Add(keyRegistration);
                    }

                    await dbContext.SaveChangesAsync(cancellationToken);
                    await transaction.CommitAsync(cancellationToken);
                    logger.LogInformation($"Request Type: {Constants.RegisterKey}, Username: {model?.Username}, UserId: {keyRegistration.UserId}, Registration: {(isNewKey ? "New" : "Updated")}, IP Address: {ipAddress}, Status: Successful");
                    return new ClientRequestResponseDto
                    {
                        Status = "201",
                        Message = "Key successfully registered"
                    };
                }

                else
                {
                    //check if CA exists, create if not
                    var caCert = await dbContext.ServerCerts.FirstOrDefaultAsync(c => c.Name == Constants.ServerCAName);
                    string caThumbprint = caCert?.Thumbprint;
                    if (caCert == null)
                    {
                        var caName = System.Environment.MachineName + "-CA";
                        var newCA = certificateGenerationService.CreateCACertificate(caName, RSAKeySize.RSA2048, HashName.SHA256, 10);
                        caThumbprint = newCA.Thumbprint;
                        caCert = new ServerCert
                        {
                            Name = Constants.ServerCAName,
                            Value = newCA.Export(X509ContentType.Cert),
                            Thumbprint = newCA.Thumbprint
                        };
                        dbContext.ServerCerts.Add(caCert);

                        CertificateUtils.InstallCertificate(new X509Certificate2(newCA.Export(X509ContentType.Pfx), "", X509KeyStorageFlags.PersistKeySet), "My");

                        var newCAPublic = new X509Certificate2(newCA.RawData);
                        CertificateUtils.InstallCertificate(newCAPublic, "Root");

                        await dbContext.SaveChangesAsync(cancellationToken);
                    }

                    if (model?.Request == Constants.GetClientRequest)
                    {
                        if (model.PubKey == null)
                            throw new Exception();

                        //check if keyblob is registered
                        var key = await dbContext.KeyRegistrations.FirstOrDefaultAsync(k => k.PublicKey == Convert.FromBase64String(model.PubKey));
                        if (key == null)
                            throw new Exception();

                        var issuer = CertificateUtils.FindCA(caThumbprint);
                        var user = await dbContext.Users.AsNoTracking().FirstOrDefaultAsync(u => u.UserId == key.UserId);
                        var device = await dbContext.Devices.AsNoTracking().FirstOrDefaultAsync(d => d.DeviceId == key.DeviceId);
                        if (user == null || device == null)
                            throw new Exception();

                        logger.LogInformation($"Request Type: {Constants.GetClientRequest}, Username: {user.UserName}, UserId: {user.UserId}, IP Address: {ipAddress}");

                        var cert = GenerateAndSignClientCert(user, device, key.KeyUsage, issuer, model.PubKey);

                        key.DateModified = DateTime.UtcNow;
                        key.Thumbprint = cert.Thumbprint;
                        await dbContext.SaveChangesAsync(cancellationToken);
                        logger.LogInformation($"Request Type: {Constants.GetClientRequest}, Username: {user.UserName}, UserId: {user.UserId}, IP Address: {ipAddress}, Status: Successful");
                        return new ClientRequestResponseDto
                        {
                            Status = "200",
                            Certificate = cert.Export(X509ContentType.Cert)
                        };

                    }
                    else if (model?.Request == Constants.GetCARequest)
                    {
                        logger.LogInformation($"Request Type: {Constants.GetCARequest}, IP Address: {ipAddress}");
                        var ca = new X509Certificate2(caCert.Value);
                        logger.LogInformation($"Request Type: {Constants.GetCARequest}, IP Address: {ipAddress}, Status: Successful");
                        return new ClientRequestResponseDto
                        {
                            Status = "200",
                            Certificate = ca.Export(X509ContentType.Cert)
                        };
                    }
                    else
                    {
                        logger.LogInformation($"Request Type: {model?.Request}, IP Address: {ipAddress}, Status: Failed");
                        return new ClientRequestResponseDto
                        {
                            Status = "400",
                            Message = "Error. Unspecificed request"
                        };
                    }
                }
            }
            catch (Exception ex)
            {
                logger.LogInformation(ex, $"Request Type: {model?.Request}, IP Address: {ipAddress}, Status: Failed");
                return new ClientRequestResponseDto
                {
                    Status = "400",
                    Message = "Error. Bad Request"
                };
            }
        }

        [HttpGet]
        public async Task<ClientRequestResponseDto> HealthCheck()
        {
            return new ClientRequestResponseDto
            {
                Status = "200",
                Message = "Health Check. Hello World!"
            };
        }

        [NonAction]
        public X509Certificate2 GenerateAndSignClientCert(User user, Device device, string keyUsage, X509Certificate2 issuer, string pubKey)
        {
            var idStrings = string.Format("{0}:{1}", user.UserId, device.DeviceId);
            var subjectKeyValuePair = new Dictionary<string, string>
            {
                { "CN", user.UserName },
                    { "L", device.DeviceName },
                    { "S", keyUsage },
                    { "T", idStrings }
                };

            return certificateGenerationService.CreateClientCertificate(subjectKeyValuePair, issuer, Certificate.HashName.SHA256, Convert.FromBase64String(pubKey));

        }
    }
}
