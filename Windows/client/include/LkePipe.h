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

#pragma once

#define PIPE_PATH L"\\\\.\\pipe\\"

#define LKE_PIPE_BUFFER_SIZE	4 * 1024

#define LKE_PIPE                PIPE_PATH L"2253A22D-BCC2-458F-9EAB-812BC901F555"

// requests
#define LKE_AUTHORIZE_KEY_USAGE	1

// parameters
#define LKE_PROCESS_ID	1