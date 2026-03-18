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
