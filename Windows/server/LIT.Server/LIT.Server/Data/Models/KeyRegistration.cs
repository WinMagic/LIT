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
    public class KeyRegistration
    {
        public int KeyRegistrationId { get; set; }
        public Guid UserId { get; set; }
        public Guid DeviceId { get; set; }
        public required byte[] PublicKey { get; set; }
        public int KeyType { get; set; }
        public required string KeyUsage { get; set; }
        public string? Thumbprint { get; set; }
        public DateTime DateCreated { get; set; }
        public DateTime DateModified { get; set; }
        public virtual User User { get; set; }
        public virtual Device Device { get; set; }
    }
}
