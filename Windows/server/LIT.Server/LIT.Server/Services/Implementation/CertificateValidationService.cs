using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using LIT.ServerMVC.Data.Models;

namespace LIT.ServerMVC.Services.Implementation
{
    public class CertificateValidationService : ICertificateValidationService
    {
        public Certificate GetCertificateSubject(X509Certificate2 clientCert)
        {
            var certSubjectArray = clientCert.Subject.Split(',');
            var userSubject = certSubjectArray.Where(a => a.Trim().StartsWith("CN")).Single();
            var userName = userSubject.Split('=')[1].Trim();
            var deviceSubject = certSubjectArray.Where(b => b.Trim().StartsWith("L")).Single();
            var deviceUniqueId = deviceSubject.Split('=')[1].Trim();
            var providerSubject = certSubjectArray.Where(c => c.Trim().StartsWith("S")).Single();
            var provider = providerSubject.Split('=')[1].Trim();
            var idsSubject = certSubjectArray.Where(d => d.Trim().StartsWith("T")).Single();
            var ids = idsSubject.Split('=')[1].Trim().Split(new[] { ":" }, StringSplitOptions.RemoveEmptyEntries);

            Certificate certSubject = new Certificate
            {
                UserName = userName,
                DeviceUniqueId = deviceUniqueId,
                Provider = provider,
                UserIndex = ids[0],
                DeviceIndex = ids[1]
            };

            return certSubject;
        }

        /// <summary>
        ///Called by SESWeb to validate the client certificate when logging in using mtls
        ///It is set to not check for certificate revocation and allow untrusted Certificate Authority
        ///It checks if the client certificate has expired and validates the issuer signature and issuer thumbprint on the certificate chain
        /// </summary>
        /// <param name="clientCert">The client certificate from the request</param>
        /// <param name="caCert">The certificate authority used to sign the client certificate and is stored on the database</param>
        /// <returns>true if client certificate is valid, has not expired and has valid signature and thumbprint, false if client certificate has expired or invalid signature or thumbprint</returns>
        public bool ValidateClientCertificateChain(X509Certificate2 clientCert, X509Certificate2 caCert)
        {
            X509Chain chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            chain.ChainPolicy.ExtraStore.Add(caCert);

            bool IsValid = chain.Build(clientCert);

            if (IsValid)
            {
                IsValid = chain.ChainElements[chain.ChainElements.Count - 1].Certificate.Thumbprint == caCert.Thumbprint;
            }

            if (IsValid)
            {
                var chainRoot = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;
                IsValid = chainRoot.Equals(caCert);
                if (IsValid)
                {
                    IsValid = caCert.RawData.SequenceEqual(chainRoot.RawData);
                }
            }
            return IsValid;
        }

        /// <summary>
        ///Called by SESWeb to validate the client certificate when logging in using mtls
        ///Verifies the signature on the certificate using the certificate authority's public key MANUALLY
        ///Does what x509Chain.Build does internally but explicitly and allows implementation of a custom certificate validation
        /// </summary>
        /// <param name="clientCert">The client certificate from the request</param>
        /// <param name="caCert">The certificate authority used to sign the client certificate and is stored on the database</param>
        /// <returns>true if certificate was issued by the CA and certificate was not tampered with, false if client certificate was not issued by the CA or certificate has been tampered with</returns>
        /// <exception cref="Exception"></exception>
        public bool ValidateClientCertificateX509Chain(X509Certificate2 clientCert, X509Certificate2 caCert)
        {
            var tbsCert = GetTBSCert(clientCert).ToArray();
            var certSignature = GetCertificateSignature(clientCert);

            HashAlgorithmName hashName = GetHashName(clientCert.SignatureAlgorithm.Value);
            if (hashName == null)
            {
                throw new Exception("Unsupported key hash algorithm.");
            }

            if (clientCert.SignatureAlgorithm.Value.StartsWith("1.2.840.113549.1.1."))
            {
                var caPublicKey = caCert.GetRSAPublicKey();
                return caPublicKey.VerifyData(tbsCert, certSignature, hashName, RSASignaturePadding.Pkcs1);
            }

            else if (clientCert.SignatureAlgorithm.Value.StartsWith("1.2.840.10045."))
            {
                var caPublicKey = caCert.GetECDsaPublicKey();
                return caPublicKey.VerifyData(tbsCert, certSignature, hashName);
            }
            else
            {
                throw new Exception("Unsupported key hash algorithm.");
            }
        }


        /// <summary>
        /// Extracts the digital signature from the specified X.509 certificate by parsing its ASN.1 structure.
        /// </summary>
        /// <param name="cert">The X.509 certificate from which to extract the signature.</param>
        /// <returns>
        /// A byte array containing the raw signature value from the certificate's ASN.1 structure.
        /// </returns>
        /// <remarks>
        /// This method performs low-level ASN.1 decoding to locate the signature field within the certificate.
        /// It navigates through the DER-encoded structure to extract the signature bit string.
        /// 
        /// The process involves:
        /// - Reading the outer certificate sequence.
        /// - Extracting the "To Be Signed" (TBS) portion.
        /// - Skipping over the algorithm identifier.
        /// - Locating and extracting the actual signature bit string.
        /// 
        /// This is useful for cryptographic validation or inspection scenarios where direct access to the signature bytes is required.
        /// </remarks>
        private byte[] GetCertificateSignature(X509Certificate2 cert)
        {
            //-----Based on the solution By Matt Nelson-White-----
            //-----From https://dev.to/-----
            //-----https://dev.to/mnelsonwhite/how-to-verify-x509-certificate-chains-2oj7-----
            var certRawData = cert.RawData;
            AsnDecoder.ReadSequence(certRawData.AsSpan(), AsnEncodingRules.DER, out var offset, out var length, out _);
            var tbsCertSpan = certRawData.AsSpan().Slice(offset, length);
            AsnDecoder.ReadSequence(tbsCertSpan, AsnEncodingRules.DER, out var tbsOffSet, out var tbsLength, out _);
            var offSetSpanstartIndex = tbsOffSet + tbsLength;
            var offSetSpanLength = tbsCertSpan.Length - offSetSpanstartIndex;
            var offSetSpan = tbsCertSpan.Slice(offSetSpanstartIndex, offSetSpanLength);
            AsnDecoder.ReadSequence(offSetSpan, AsnEncodingRules.DER, out var algOffSet, out var algLength, out _);
            var signatureStartIndex = algOffSet + algLength;
            var signatureLength = offSetSpan.Length - signatureStartIndex;
            var signature = offSetSpan.Slice(signatureStartIndex, signatureLength);

            return AsnDecoder.ReadBitString(signature, AsnEncodingRules.DER, out _, out _);
        }


        /// <summary>
        /// Extracts the "To Be Signed" (TBS) portion of the specified X.509 certificate, including its ASN.1 header.
        /// </summary>
        /// <param name="cert">The X.509 certificate from which to extract the TBS section.</param>
        /// <returns>
        /// A <see cref="Span{Byte}"/> representing the TBS portion of the certificate, including the ASN.1 header bytes.
        /// </returns>
        /// <remarks>
        /// The TBS section contains all the certificate fields that are signed by the issuer, such as subject, issuer, validity period, and public key.
        /// 
        /// This method:
        /// - Reads the outer sequence of the DER-encoded certificate.
        /// - Locates the TBS section within the ASN.1 structure.
        /// - Returns a span that includes the TBS data along with its header (by offsetting 4 bytes backward).
        /// 
        /// This is useful for scenarios such as signature verification, certificate inspection, or custom certificate processing.
        /// </remarks>
        private Span<byte> GetTBSCert(X509Certificate2 cert)
        {
            //-----Based on the solution By Matt Nelson-White-----
            //-----From https://dev.to/-----
            //-----https://dev.to/mnelsonwhite/how-to-verify-x509-certificate-chains-2oj7-----
            var certRawData = cert.RawData;
            AsnDecoder.ReadSequence(certRawData.AsSpan(), AsnEncodingRules.DER, out var offset, out var length, out _);
            var tbsCertSpan = certRawData.AsSpan().Slice(offset, length);
            AsnDecoder.ReadSequence(tbsCertSpan, AsnEncodingRules.DER, out var tbsOffSet, out var tbsLength, out _);

            return tbsCertSpan.Slice(tbsOffSet - 4, tbsLength + 4);
        }

        private HashAlgorithmName GetHashName(string sigAlgoValue)
        {
            HashAlgorithmName hashAlgorithmName;
            switch (sigAlgoValue)
            {
                case "1.2.840.113549.1.1.11":
                    hashAlgorithmName = HashAlgorithmName.SHA256;
                    break;
                case "1.2.840.113549.1.1.12":
                    hashAlgorithmName = HashAlgorithmName.SHA384;
                    break;
                case "1.2.840.113549.1.1.13":
                    hashAlgorithmName = HashAlgorithmName.SHA512;
                    break;
                case "1.2.840.10045.4.3.2":
                    hashAlgorithmName = HashAlgorithmName.SHA256;
                    break;
                case "1.2.840.10045.4.3.3":
                    hashAlgorithmName = HashAlgorithmName.SHA384;
                    break;
                case "1.2.840.10045.4.3.4":
                    hashAlgorithmName = HashAlgorithmName.SHA512;
                    break;
                default:
                    hashAlgorithmName = HashAlgorithmName.SHA256;
                    break;
            }
            return hashAlgorithmName;
        }

    }
}
