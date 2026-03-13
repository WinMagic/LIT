using LIT.ServerMVC.Data.Models;
using System.Security.Cryptography.X509Certificates;

namespace LIT.ServerMVC.Services
{
    public interface ICertificateValidationService
    {
        bool ValidateClientCertificateChain(X509Certificate2 clientCert, X509Certificate2 caCert);
        bool ValidateClientCertificateX509Chain(X509Certificate2 clientCert, X509Certificate2 caCert);
        Certificate GetCertificateSubject(X509Certificate2 clientCert);
    }
}
