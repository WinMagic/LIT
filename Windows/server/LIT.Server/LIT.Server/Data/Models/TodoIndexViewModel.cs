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
    public class TodoIndexViewModel
    {
        public bool IsHttps { get; init; }
        public bool CertificatePresented { get; init; }
        public bool IsAuthenticated { get; init; }
        public string? UserName { get; init; }
        public string? DeviceName { get; init; }
        public List<TodoItem> Tasks { get; init; } = new();
    }
}
