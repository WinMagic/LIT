/*
* Copyright (C) 2026 WinMagic Inc.
*
* This file is part of the WinMagic LIT reference project.
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* Alternatively, this file may be used under the terms of the WinMagic Inc.
* Commercial License, which can be found at https://winmagic.com/en/legal/commercial_license/
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

using LIT.ServerMVC.Commons;
using LIT.ServerMVC.Data;
using LIT.ServerMVC.Data.Models;
using LIT.ServerMVC.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace LIT.ServerMVC.Controllers
{
    public class AccountController(ApplicationDbContext dbContext, ICertificateValidationService certificateValidationService, ILogger<AccountController> logger) : Controller
    {
        [AllowAnonymous]
        [HttpGet]
        public async Task<IActionResult> Login(string? returnUrl = null, bool logoutWithCert = false)
        {
            var certificate = HttpContext.Connection.ClientCertificate;
            if (certificate != null && !logoutWithCert)
            {
                var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
                try
                {
                    var dictionary = await LoginWithCert(certificate);
                    TempData["Message"] = $"User: {dictionary["User"]}, Device: {dictionary["Device"]} has successfully logged in";
                    logger.LogInformation($"User: {dictionary["User"]} has logged in using certificate IP Address: {ipAddress}");
                    return RedirectToAction("Index", "TodoItem");
                }
                catch (Exception ex)
                {
                    logger.LogInformation($"Attempt to login using certificate failed. IP Address: {ipAddress}");
                    ModelState.AddModelError(string.Empty, ex.Message);
                    return View();
                }
            }


            if (User.Identity?.IsAuthenticated == true)
            {

                if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                    return Redirect(returnUrl);

                return RedirectToAction("Index", "TodoItem");
            }

            ViewBag.ReturnUrl = returnUrl;

            if (TempData.TryGetValue("LoginError", out var loginError) && loginError is string loginMsg && !string.IsNullOrEmpty(loginMsg))
            {
                ModelState.AddModelError(string.Empty, loginMsg);
            }

            return View();
        }

        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
        {
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            logger.LogInformation($"User: {model.UserName} attempting to login using password IP Address: {ipAddress}");
            if (!ModelState.IsValid)
            {
                ViewBag.ReturnUrl = returnUrl;
                return View(model);
            }

            var user = await ValidateUserAsync(model.UserName, model.Password);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "Invalid username or password.");
                ViewBag.ReturnUrl = returnUrl;
                return View(model);
            }

            await SignInUserAsync(user.UserId.ToString(), model.UserName);

            if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                return Redirect(returnUrl);

            TempData["Message"] = $"User {model.UserName} has successfully logged in";
            logger.LogInformation($"User: {model.UserName} has logged in using password IP Address: {ipAddress}");
            return RedirectToAction("Index", "TodoItem");
        }

        [HttpGet]
        public async Task<IActionResult> Logout()
        {
            var logoutWithCert = HttpContext.Connection.ClientCertificate != null;
            await HttpContext.SignOutAsync("AppCookie");
            return RedirectToAction("Login", new { logoutWithCert });
        }

        private async Task<Data.Models.User?> ValidateUserAsync(string username, string password)
        {
            var user = await dbContext.Users.FirstOrDefaultAsync(u => u.UserName == username);
            if (user == null)
                return null;

            if (!Utils.VerifyHashedPassword(user.Password, password))
                return null;

            return user;
        }


        private async Task<Dictionary<string, string>> LoginWithCert(X509Certificate2 certificate)
        {
            //var model = new LoginViewModel();
            var certSubject = new Certificate();
            try
            {
                certSubject = certificateValidationService.GetCertificateSubject(certificate);
            }
            catch (Exception)
            {
                throw new Exception("Error getting certificate subject");
            }


            try
            {
                var IsUserGuidValid = Guid.TryParse(certSubject.UserIndex, out var userGuid);
                var IsDeviceGuidValid = Guid.TryParse(certSubject.DeviceIndex, out var deviceGuid);
                if (!IsUserGuidValid || !IsDeviceGuidValid)
                    throw new Exception("Invalid Guids on certificate subject field");


                var user = await dbContext.Users.FirstOrDefaultAsync(u => u.UserId == userGuid);
                var device = await dbContext.Devices.FirstOrDefaultAsync(d => d.DeviceId == deviceGuid);
                if (user == null || device == null)
                    throw new Exception("User or Device does not exist");

                var key = await dbContext.KeyRegistrations
                    .Where(k => k.UserId == userGuid && k.DeviceId == deviceGuid && k.KeyUsage == certSubject.Provider)
                    .OrderByDescending(k => k.DateCreated)
                    .FirstOrDefaultAsync();

                if (key == null)
                    throw new Exception("Certificate registration does not exist");

                var IsKeyRegistered = CompareECCKeys(certificate.GetECDsaPublicKey(), key.PublicKey);
                if (!IsKeyRegistered)
                    throw new Exception("Certificate public key not registered");

                var serverCACert = dbContext.ServerCerts.FirstOrDefault(sc => sc.Name == Constants.ServerCAName);
                var caCert = new X509Certificate2(serverCACert.Value);
                if (!certificateValidationService.ValidateClientCertificateX509Chain(certificate, caCert)
                    || !certificateValidationService.ValidateClientCertificateChain(certificate, caCert))
                    throw new Exception("Certificate failed validation");

                await SignInUserAsync(user.UserId.ToString(), user.UserName);
                var dictionary = new Dictionary<string, string>();
                dictionary.Add("User", user.UserName);
                dictionary.Add("Device", device.DeviceName);
                return dictionary;
            }
            catch(Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        private async Task SignInUserAsync(string userId, string username)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, userId),
                new Claim(ClaimTypes.Name, username)
            };

            var claimsIdentity = new ClaimsIdentity(claims, authenticationType: "AppCookie");
            var principal = new ClaimsPrincipal(claimsIdentity);

            await HttpContext.SignInAsync("AppCookie", principal);
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
    }
}
