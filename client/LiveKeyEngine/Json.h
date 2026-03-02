#pragma once

#include <string>
#include <unordered_map>
#include <stdexcept>
#include <cctype>

std::unordered_map<std::string, std::string> parse_flat_json_to_strings(const std::string& json);
std::string map_to_flat_json(const std::unordered_map<std::string, std::string>& m);
