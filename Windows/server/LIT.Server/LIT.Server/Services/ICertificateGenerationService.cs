using LIT.ServerMVC.Data.Models;
using System.Security.Cryptography.X509Certificates;

namespace LIT.ServerMVC.Services
{
    public interface ICertificateGenerationService
    {
        X509Certificate2 CreateCACertificate(string certSubjectName, Certificate.RSAKeySize keySize, Certificate.HashName hashName, int yearExpiry = 0);
        X509Certificate2 CreateCACertificate(string certSubjectName, Certificate.ECCCurves curve, Certificate.HashName hashName, int yearExpiry = 0);
        X509Certificate2 CreateClientCertificate(Dictionary<string, string> subjectKeyValuePair, X509Certificate2 caCertificate, Certificate.HashName hashName, byte[] publicKeyBlob);
        byte[] CreateClientCertificate(Dictionary<string, string> subjectKeyValuePair, X509Certificate2 caCertificate, Certificate.HashName hashName, Certificate.ECCCurves eccCurve);
        byte[] CreateClientCertificate(Dictionary<string, string> subjectKeyValuePair, X509Certificate2 caCertificate, Certificate.HashName hashName, Certificate.RSAKeySize keySize);
    }
}
