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

namespace LIT.ServerMVC.Data.Models
{
    public class Certificate
    {
        public static string ClientAuthOid = "1.3.6.1.5.5.7.3.2";
        public static string RSAEncryptionOid = "1.2.840.113549.1.1.";
        public static string ECCEncryptionOid = "1.2.840.10045.";

        public string UserName;
        public string DeviceUniqueId;
        public string Provider;
        public string UserIndex;
        public string DeviceIndex;

        public enum RSAKeySize
        {
            RSA2048 = 2048,
            RSA4096 = 4096
        }

        public enum HashName
        {
            SHA256 = 1,
            SHA384 = 2,
            SHA512 = 3
        }

        public enum ECCCurves
        {
            ECC256 = 1,
            ECC384 = 2,
            ECC521 = 3
        }
    }
}
