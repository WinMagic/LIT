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

#include <string>
#include <unordered_map>
#include <stdexcept>
#include <cctype>

std::unordered_map<std::string, std::string> parse_flat_json_to_strings(const std::string& json);
std::string map_to_flat_json(const std::unordered_map<std::string, std::string>& m);
