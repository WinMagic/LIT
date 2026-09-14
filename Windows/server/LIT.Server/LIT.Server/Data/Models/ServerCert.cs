/*
* Copyright (c) 2026 WinMagic Corp.
* This file is part of the WinMagic LIT reference project.
* This software is dual-licensed:
* 
* 1. GNU Affero General Public License v3.0 (AGPL-3.0)
* 2. Commercial license available from WinMagic Corp.
* 
* You may use this file under the terms of the AGPL-3.0 license
* included in the LICENSE file in the root of this repository.
* 
* For commercial licensing options, OEM redistribution rights,
* proprietary use, or support agreements, please contact WinMagic.
*/

namespace LIT.ServerMVC.Data.Models
{
    public class ServerCert
    {
        public int Index { get; set; }
        public required string Name { get; set; }
        public required byte[] Value { get; set; }
        public required string Thumbprint { get; set; }
        public DateTime DateCreated { get; set; }
    }
}
