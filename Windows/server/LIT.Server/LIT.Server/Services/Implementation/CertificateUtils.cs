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
