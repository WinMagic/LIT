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
    public class ClientRequestApiController(ApplicationDbContext dbContext, ICertificateGenerationService certificateGenerationService) : ControllerBase
    {
        [HttpPost]
        public async Task<ClientRequestResponseDto> DoClientRequests(ClientRequestDto model, CancellationToken cancellationToken)
        {
            if (model?.Request == Constants.RegisterKey)
            {
                if (String.IsNullOrEmpty(model.DeviceName) || String.IsNullOrEmpty(model.Username) || String.IsNullOrEmpty(model.PubKey))
                    throw new Exception();

                //var password = String.IsNullOrEmpty(model.Password) ? Utils.Generate() : model.Password;
                //var hashedPassword = Utils.HashPassword(password);

                var user = await dbContext.Users.FirstOrDefaultAsync(u => u.UserName == model.Username);
                var device = await dbContext.Devices.FirstOrDefaultAsync(d => d.DeviceName == model.DeviceName);
                if (user == null && device == null)
                {
                    //create User
                    user = new User
                    {
                        UserId = new Guid(),
                        UserName = model.Username,
                        Password = model.Username,
                    };

                    //create Device
                    device = new Device
                    {
                        DeviceId = new Guid(),
                        DeviceName = model.DeviceName
                    };

                    dbContext.Users.Add(user);
                    dbContext.Devices.Add(device);
                }
                else
                {
                    user.UserName = model.Username;
                    user.Password = model.Password;
                    device.DeviceName = model.DeviceName;
                }
                await dbContext.SaveChangesAsync(cancellationToken);

                var keyRegistration = new KeyRegistration
                {
                    UserId = user.UserId,
                    DeviceId = device.DeviceId,
                    PublicKey = Convert.FromBase64String(model.PubKey),
                    KeyType = model.KeyType ?? 0,
                    KeyUsage = model.KeyUsage
                };

                dbContext.KeyRegistrations.Add(keyRegistration);
                await dbContext.SaveChangesAsync(cancellationToken);

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

                    CertificateUtils.InstallCertificate(new X509Certificate2(newCA.Export(X509ContentType.Pfx), "", X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable), "My");

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

                    var cert = GenerateAndSignClientCert(user, device, key.KeyUsage, issuer, model.PubKey);

                    key.DateModified = DateTime.UtcNow;
                    key.Thumbprint = cert.Thumbprint;
                    await dbContext.SaveChangesAsync(cancellationToken);

                    return new ClientRequestResponseDto
                    {
                        Status = "200",
                        Certificate = cert.Export(X509ContentType.Cert)
                    };

                }
                else if (model?.Request == Constants.GetCARequest)
                {
                    var ca = new X509Certificate2(caCert.Value);
                    return new ClientRequestResponseDto
                    {
                        Status = "200",
                        Certificate = ca.Export(X509ContentType.Cert)
                    };
                }
                else
                {
                    return new ClientRequestResponseDto
                    {
                        Status = "400",
                        Message = "Error. Unspecificed request"
                    };
                }
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
