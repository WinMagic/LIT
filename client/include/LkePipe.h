/*
* Copyright (C) 2026 WinMagic Inc.
*
* This file is part of the WinMagic Key Storage Provider..
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

#pragma once

#define PIPE_PATH L"\\\\.\\pipe\\"

#define LKE_PIPE_BUFFER_SIZE	4 * 1024

#define LKE_PIPE                PIPE_PATH L"2253A22D-BCC2-458F-9EAB-812BC901F555"

// requests
#define LKE_AUTHORIZE_KEY_USAGE	1

// parameters
#define LKE_PROCESS_ID	1