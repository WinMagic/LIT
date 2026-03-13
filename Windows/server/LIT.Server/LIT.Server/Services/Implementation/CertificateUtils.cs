using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace LIT.ServerMVC.Services.Implementation
{
    public static class CertificateUtils
    {
        public static byte[] GenerateSerialNumber(int size = 16)
        {
            byte[] serial = new byte[size];
            using (var rnd = RandomNumberGenerator.Create())
            {
                do
                {
                    rnd.GetBytes(serial);
                }
                while (IsSerialAllZeroes(serial));
            }
            return serial;
        }

        public static void InstallCertificate(X509Certificate2 certificate, string storeName)
        {
            using (var store = new X509Store(storeName, StoreLocation.LocalMachine))
            {
                store.Open(OpenFlags.MaxAllowed);
                store.Add(certificate);
                store.Close();
            }
        }

        private static bool IsSerialAllZeroes(byte[] serial)
        {
            foreach (var b in serial)
            {
                if (b != 0)
                {
                    return false; //returns false if byte is not zero, ending the GenerateSerialNumber do while loop
                }
            }
            return true; // all bytes were zero, continue the do while loop
        }

        public static X509Certificate2 FindCA(string thumbprint)
        {
            using (var store = new X509Store("My", StoreLocation.LocalMachine))
            {
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                var ca = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint.ToUpper(), validOnly: true);
                return ca.Count > 0 ? ca[0] : null;
            }
        }
    }
}
