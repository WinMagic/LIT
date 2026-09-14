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

void logprintf(int level, const char* format, ...);

#define LOG_LEVEL_DISABLED  0
#define LOG_LEVEL_ERROR     1
#define LOG_LEVEL_INFO      2
#define LOG_LEVEL_DEBUG     3

#define LOG(level, fmt, ...) \
    logprintf(level, fmt, ##__VA_ARGS__)

// convenience wrappers
#define LOGE(fmt, ...) LOG(LOG_LEVEL_ERROR,  fmt, ##__VA_ARGS__)
#define LOGI(fmt, ...) LOG(LOG_LEVEL_INFO,  fmt, ##__VA_ARGS__)
#define LOGD(fmt, ...) LOG(LOG_LEVEL_DEBUG, fmt, ##__VA_ARGS__)


