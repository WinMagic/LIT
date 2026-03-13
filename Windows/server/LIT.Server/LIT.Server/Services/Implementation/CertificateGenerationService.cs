using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using LIT.ServerMVC.Data.Models;

namespace LIT.ServerMVC.Services.Implementation
{
    public class CertificateGenerationService : ICertificateGenerationService
    {
        List<string> ClientCertificateSupportedBlobFormats = new List<string> { "ECS1", "ECS3", "ECS5", "RSA1" };

        //example subjectKeyValuePair
        //Key: CN, Value: userName
        //Key: L, Value: deviceUniqueId

        //rsa

        /// <summary>
        /// Creates a self-signed Certificate Authority (CA) certificate using RSA cryptography with the specified subject name, key size, and hash algorithm.
        /// </summary>
        /// <param name="certSubjectName">The subject name for the certificate (e.g., "MyRootCA").</param>
        /// <param name="keySize">The RSA key size to use for the certificate (e.g., 2048, 4096).</param>
        /// <param name="hashName">The hash algorithm to use for signing the certificate (e.g., SHA256, SHA512).</param>
        /// <param name="yearExpiry">The number of years until the certificate expires. Defaults to 10 years if set to 0.</param>
        /// <returns>
        /// A self-signed <see cref="X509Certificate2"/> object representing the CA certificate.
        /// </returns>
        /// <exception cref="ArgumentException">Thrown when <paramref name="certSubjectName"/> is null or empty.</exception>
        public X509Certificate2 CreateCACertificate(string certSubjectName, Certificate.RSAKeySize keySize, Certificate.HashName hashName, int yearExpiry = 0)
        {
            if (string.IsNullOrEmpty(certSubjectName))
                throw new ArgumentException("Certificate subject name cannot be null or empty");

            HashAlgorithmName hashAlgorithmName = GetHashName(hashName);

            using (RSA rsa = RSA.Create((int)keySize))
            {
                var certRequest = new CertificateRequest($"CN={certSubjectName}", rsa, hashAlgorithmName, RSASignaturePadding.Pkcs1);
                certRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, false));
                certRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature, true));
                certRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(certRequest.PublicKey, false));

                yearExpiry = yearExpiry == 0 ? 10 : yearExpiry;
                return certRequest.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(yearExpiry));
            }
        }

        //ecc

        /// <summary>
        /// Creates a self-signed Certificate Authority (CA) certificate using Elliptic Curve Cryptography (ECC) with the specified subject name, curve, and hash algorithm..
        /// </summary>
        /// <param name="certSubjectName">The subject name for the certificate (e.g., "MyECCRootCA").</param>
        /// <param name="curve">The ECC curve to use for key generation (e.g., NistP256, NistP384).</param>
        /// <param name="hashName">The hash algorithm to use for signing the certificate (e.g., SHA256, SHA384).</param>
        /// <param name="yearExpiry">The number of years until the certificate expires. Defaults to 10 years if set to 0.</param>
        /// <returns>
        /// A self-signed <see cref="X509Certificate2"/> object representing the ECC-based CA certificate.
        /// </returns>
        /// <exception cref="ArgumentException">Thrown when <paramref name="certSubjectName"/> is null or empty.</exception>
        public X509Certificate2 CreateCACertificate(string certSubjectName, Certificate.ECCCurves curve, Certificate.HashName hashName, int yearExpiry = 0)
        {
            if (string.IsNullOrEmpty(certSubjectName))
                throw new ArgumentException("Certificate subject name cannot be null or empty");

            HashAlgorithmName hashAlgorithmName = GetHashName(hashName);
            ECCurve eccCurve = GetCurveName(curve);

            using (ECDsa ecc = ECDsa.Create(eccCurve))
            {
                var subjectField = new X500DistinguishedName($"CN={certSubjectName}");
                var certRequest = new CertificateRequest(subjectField, ecc, hashAlgorithmName);
                certRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, false));
                certRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature, true));
                certRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(certRequest.PublicKey, false));

                yearExpiry = yearExpiry == 0 ? 10 : yearExpiry;
                return certRequest.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(yearExpiry));
            }
        }

        //ecc or rsa
        //expects the ecc or rsa public key blob to be of CNG format

        /// <summary>
        /// Creates a client certificate using the provided public key blob and signs it with the specified Certificate Authority (CA) certificate.
        /// </summary>
        /// <param name="subjectKeyValuePair">
        /// A dictionary containing subject name components (e.g., CN, O, OU, etc.) used to build the certificate's distinguished name.
        /// </param>
        /// <param name="caCertificate">
        /// The CA certificate used to sign the client certificate. Must be RSA or ECC-based.
        /// </param>
        /// <param name="hashName">
        /// The hash algorithm to use for signing the certificate (e.g., SHA256, SHA384).
        /// </param>
        /// <param name="publicKeyBlob">
        /// A byte array representing the public key blob. Must be in CNG format RSA or ECC.
        /// </param>
        /// <returns>
        /// A signed <see cref="X509Certificate2"/> object representing the client certificate.
        /// </returns>
        /// <exception cref="Exception">
        /// Thrown when the public key format is unsupported or the CA certificate's key type is invalid.
        /// </exception>
        public X509Certificate2 CreateClientCertificate(Dictionary<string, string> subjectKeyValuePair, X509Certificate2 caCertificate, Certificate.HashName hashName, byte[] publicKeyBlob)
        {
            var keyFormat = Encoding.ASCII.GetString(publicKeyBlob, 0, 4);
            if (!ClientCertificateSupportedBlobFormats.Contains(keyFormat))
                throw new Exception("Key Format not supported");

            var subjectFieldString = String.Join(", ", subjectKeyValuePair.Select(kv => String.Format("{0}={1}", kv.Key, kv.Value)));
            HashAlgorithmName hashAlgorithmName = GetHashName(hashName);

            if (!caCertificate.PublicKey.Oid.Value.StartsWith(Certificate.RSAEncryptionOid) && !caCertificate.PublicKey.Oid.Value.StartsWith(Certificate.ECCEncryptionOid))
                throw new Exception("CA Certificate key type is not supported");

            if (keyFormat == "RSA1")
            {
                return CreateRSACertificate(publicKeyBlob, subjectFieldString, hashAlgorithmName, caCertificate);
            }
            else
            {
                return CreateECCCertificate(publicKeyBlob, subjectFieldString, hashAlgorithmName, caCertificate);
            }
        }

        //ecc key
        //generate both public and private key

        /// <summary>
        /// Creates a client certificate using a newly generated ECC key pair and signs it with the specified Certificate Authority (CA) certificate.
        /// The certificate is exported as a PFX byte array.
        /// </summary>
        /// <param name="subjectKeyValuePair">
        /// A dictionary containing subject name components (e.g., CN, O, OU, etc.) used to build the certificate's distinguished name.
        /// </param>
        /// <param name="caCertificate">
        /// The CA certificate used to sign the client certificate. Must be RSA or ECC-based.
        /// </param>
        /// <param name="hashName">
        /// The hash algorithm to use for signing the certificate (e.g., SHA256, SHA384).
        /// </param>
        /// <param name="eccCurve">
        /// The ECC curve to use for generating the key pair (e.g., NistP256, NistP384).
        /// </param>
        /// <returns>
        /// A byte array containing the PFX representation of the signed client certificate, including the private key.
        /// </returns>
        /// <exception cref="Exception">
        /// Thrown when the CA certificate's key type is invalid or unsupported.
        /// </exception>
        public byte[] CreateClientCertificate(Dictionary<string, string> subjectKeyValuePair, X509Certificate2 caCertificate, Certificate.HashName hashName, Certificate.ECCCurves eccCurve)
        {
            var subjectFieldString = String.Join(", ", subjectKeyValuePair.Select(kv => String.Format("{0}={1}", kv.Key, kv.Value)));
            HashAlgorithmName hashAlgorithmName = GetHashName(hashName);

            ECCurve curve = GetCurveName(eccCurve);
            using (var ecc = ECDsa.Create(curve))
            {
                var subjectField = new X500DistinguishedName(subjectFieldString);
                var certRequest = new CertificateRequest(subjectField, ecc, hashAlgorithmName);

                var cert = CreateAndSignClientCertificate(caCertificate, certRequest, Certificate.ECCEncryptionOid);
                cert = cert.CopyWithPrivateKey(ecc);
                return cert.Export(X509ContentType.Pfx);
            }
        }

        //rsa key
        //generate both public and private key

        /// <summary>
        /// Creates a client certificate using a newly generated RSA key pair and signs it with the specified Certificate Authority (CA) certificate.
        /// The certificate is exported as a PFX byte array.
        /// </summary>
        /// <param name="subjectKeyValuePair">
        /// A dictionary containing subject name components (e.g., CN, O, OU, etc.) used to build the certificate's distinguished name.
        /// </param>
        /// <param name="caCertificate">
        /// The CA certificate used to sign the client certificate. Must be RSA or ECC-based.
        /// </param>
        /// <param name="hashName">
        /// The hash algorithm to use for signing the certificate (e.g., SHA256, SHA512).
        /// </param>
        /// <param name="keySize">
        /// The RSA key size to use for generating the key pair (e.g., 2048, 4096).
        /// </param>
        /// <returns>
        /// A byte array containing the PFX representation of the signed client certificate, including the private key.
        /// </returns>
        /// <exception cref="Exception">
        /// Thrown when the CA certificate's key type is invalid or unsupported.
        /// </exception>

        public byte[] CreateClientCertificate(Dictionary<string, string> subjectKeyValuePair, X509Certificate2 caCertificate, Certificate.HashName hashName, Certificate.RSAKeySize keySize)
        {
            var subjectFieldString = String.Join(", ", subjectKeyValuePair.Select(kv => String.Format("{0}={1}", kv.Key, kv.Value)));
            HashAlgorithmName hashAlgorithmName = GetHashName(hashName);

            using (RSA rsa = RSA.Create((int)keySize))
            {
                var subjectField = new X500DistinguishedName(subjectFieldString);
                var certRequest = new CertificateRequest(subjectField, rsa, hashAlgorithmName, RSASignaturePadding.Pkcs1);

                var cert = CreateAndSignClientCertificate(caCertificate, certRequest, Certificate.RSAEncryptionOid);
                cert = cert.CopyWithPrivateKey(rsa);
                return cert.Export(X509ContentType.Pfx);
            }
        }

        private X509Certificate2 CreateRSACertificate(byte[] publicKeyBlob, string subjectFieldString, HashAlgorithmName hashAlgorithmName, X509Certificate2 caCertificate)
        {
            var cngKey = CngKey.Import(publicKeyBlob, CngKeyBlobFormat.GenericPublicBlob);
            using (RSA rsa = new RSACng(cngKey))
            {
                var subjectField = new X500DistinguishedName(subjectFieldString);
                var certRequest = new CertificateRequest(subjectField, rsa, hashAlgorithmName, RSASignaturePadding.Pkcs1);
                return CreateAndSignClientCertificate(caCertificate, certRequest, Certificate.RSAEncryptionOid);
            }
        }

        private X509Certificate2 CreateECCCertificate(byte[] publicKeyBlob, string subjectFieldString, HashAlgorithmName hashAlgorithmName, X509Certificate2 caCertificate)
        {
            var cngKey = CngKey.Import(publicKeyBlob, CngKeyBlobFormat.EccPublicBlob);
            using (ECDsa ecc = new ECDsaCng(cngKey))
            {
                var subjectField = new X500DistinguishedName(subjectFieldString);
                var certRequest = new CertificateRequest(subjectField, ecc, hashAlgorithmName);
                return CreateAndSignClientCertificate(caCertificate, certRequest, Certificate.ECCEncryptionOid);
            }
        }

        private X509Certificate2 CreateAndSignClientCertificate(X509Certificate2 caCertificate, CertificateRequest certRequest, string certRequestEncryptionOid)
        {
            string caEncryptionOid = caCertificate.PublicKey.Oid.Value;

            var serialNumberBytes = CertificateUtils.GenerateSerialNumber(16);

            certRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
            certRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            certRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(certRequest.PublicKey, false));
            certRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(Certificate.ClientAuthOid) }, critical: true));

            //check if both ca and certRequest have same key type
            if (caEncryptionOid.StartsWith(certRequestEncryptionOid))
            {
                return certRequest.Create(caCertificate, DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1), serialNumberBytes);
            }
            //if not same key type use sigGenerator to sign the certRequest
            else
            {
                X509SignatureGenerator sigGenerator = null;
                //ca certs with rsa key type
                if (caEncryptionOid.StartsWith(Certificate.RSAEncryptionOid))
                {
                    using (var rsa = caCertificate.GetRSAPrivateKey())
                    {
                        sigGenerator = X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1);
                        return certRequest.Create(caCertificate.SubjectName, sigGenerator, DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1), serialNumberBytes);
                    }
                }
                //ca certs with ecc key type
                else if (caEncryptionOid.StartsWith(Certificate.ECCEncryptionOid))
                {
                    using (var ecc = caCertificate.GetECDsaPrivateKey())
                    {
                        sigGenerator = X509SignatureGenerator.CreateForECDsa(ecc);
                        return certRequest.Create(caCertificate.SubjectName, sigGenerator, DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1), serialNumberBytes);
                    }
                }
                else { throw new Exception("CA Certificate key type is not supported"); }
            }
        }

        private HashAlgorithmName GetHashName(Certificate.HashName hashName)
        {
            HashAlgorithmName result;
            switch (hashName)
            {
                case Certificate.HashName.SHA256:
                    result = HashAlgorithmName.SHA256;
                    break;
                case Certificate.HashName.SHA384:
                    result = HashAlgorithmName.SHA384;
                    break;
                case Certificate.HashName.SHA512:
                    result = HashAlgorithmName.SHA512;
                    break;
                default:
                    result = HashAlgorithmName.SHA256;
                    break;
            }
            return result;
        }

        private ECCurve GetCurveName(Certificate.ECCCurves curve)
        {
            ECCurve eccCurve;
            switch (curve)
            {
                case Certificate.ECCCurves.ECC256:
                    eccCurve = ECCurve.NamedCurves.nistP256;
                    break;
                case Certificate.ECCCurves.ECC384:
                    eccCurve = ECCurve.NamedCurves.nistP384;
                    break;
                case Certificate.ECCCurves.ECC521:
                    eccCurve = ECCurve.NamedCurves.nistP521;
                    break;
                default:
                    eccCurve = ECCurve.NamedCurves.nistP256;
                    break;
            }
            return eccCurve;
        }
    }
}
