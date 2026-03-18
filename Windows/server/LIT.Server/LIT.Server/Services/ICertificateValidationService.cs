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
    public interface ICertificateValidationService
    {
        bool ValidateClientCertificateChain(X509Certificate2 clientCert, X509Certificate2 caCert);
        bool ValidateClientCertificateX509Chain(X509Certificate2 clientCert, X509Certificate2 caCert);
        Certificate GetCertificateSubject(X509Certificate2 clientCert);
    }
}
