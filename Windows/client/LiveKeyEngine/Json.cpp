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

#include "Json.h"

#include <string>
#include <unordered_map>
#include <cctype>


// Trim helpers
static inline void ltrim(const char*& p) { while (std::isspace(static_cast<unsigned char>(*p))) ++p; }
static inline void rtrim(std::string& s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
}

/*
 parse_string:
  p - In/out cursor into a null-terminated JSON buffer. On entry it must point
      at the opening double quote ('"'). The function advances it past the
      closing quote and returns the decoded string contents. Supports the
      standard simple escapes: \" \\ \/ \b \f \n \r \t. Throws on unsupported
      escapes or if the string is unterminated.

 Returns: std::string containing the decoded characters with escapes resolved.
*/
static std::string parse_string(const char*& p) {
    if (*p != '"') throw std::runtime_error("Expected '\"' at string start");
    ++p; // skip opening quote
    std::string out;
    for (;;) {
        char c = *p++;
        if (c == '\0') throw std::runtime_error("Unterminated string");
        if (c == '"') break;          // end quote
        if (c == '\\') {              // basic escapes
            char e = *p++;
            switch (e) {
            case '"': out.push_back('"'); break;
            case '\\': out.push_back('\\'); break;
            case '/': out.push_back('/'); break;
            case 'b': out.push_back('\b'); break;
            case 'f': out.push_back('\f'); break;
            case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break;
            case 't': out.push_back('\t'); break;
                // Minimal: skip \uXXXX handling; add if needed
            default: throw std::runtime_error("Unsupported escape");
            }
        }
        else {
            out.push_back(c);
        }
    }
    return out;
}

static std::string parse_literal(const char*& p) {
    // Reads until delimiter , } or whitespace. For numbers/bool/null as raw token
    const char* start = p;
    while (*p && *p != ',' && *p != '}' && !std::isspace(static_cast<unsigned char>(*p))) ++p;
    return std::string(start, p - start);
}

/*
 parse_flat_json_to_strings:
  json - UTF-8 JSON text expected to be a flat object (no nesting), e.g.
         {"k1":"v1","k2":123,"k3":true}. The parser:
           - Skips leading whitespace.
           - Requires an opening '{' and a matching closing '}'.
           - Reads each key as a quoted JSON string via parse_string().
           - After ':', reads the value either as a quoted string
             (parse_string) or as an unquoted literal (number/true/false/null)
             via parse_literal(), storing the literal text.
           - Accepts comma-separated pairs and stops at '}'.
           - Throws std::runtime_error on malformed input
             (missing separators, bad quotes, trailing characters, etc.).

 Returns: std::unordered_map<std::string, std::string> where each entry maps the
          object key to the value as text (string values unescaped; non-strings
          kept as their literal token).
*/
std::unordered_map<std::string, std::string> parse_flat_json_to_strings(const std::string& json) {
    const char* p = json.c_str();
    ltrim(p);
    if (*p != '{') throw std::runtime_error("Expected '{'");
    ++p;
    std::unordered_map<std::string, std::string> result;

    for (;;) {
        ltrim(p);
        if (*p == '}') { ++p; break; }       // empty object
        // key
        std::string key = parse_string(p);

        ltrim(p);
        if (*p != ':') throw std::runtime_error("Expected ':'");
        ++p;

        ltrim(p);
        std::string value;
        if (*p == '"') {
            value = parse_string(p);
        }
        else {
            value = parse_literal(p);        // number, true, false, null (as string)
        }

        // store
        result.emplace(std::move(key), std::move(value));

        ltrim(p);
        if (*p == ',') { ++p; continue; }
        if (*p == '}') { ++p; break; }
        throw std::runtime_error("Expected ',' or '}'");
    }

    ltrim(p);
    if (*p != '\0') throw std::runtime_error("Trailing characters");
    return result;
}


// Escape a JSON string (basic escapes)
static std::string JsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);

    for (char c : s) {
        switch (c) {
        case '\"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b";  break;
        case '\f': out += "\\f";  break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            // Control characters must be escaped
            if (static_cast<unsigned char>(c) < 0x20) {
                char buf[7];
                std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                out += buf;
            }
            else {
                out.push_back(c);
            }
        }
    }
    return out;
}

// Detect if a value is already a JSON literal
static bool IsJsonLiteral(const std::string& v) {
    if (v == "null" || v == "true" || v == "false")
        return true;

    // Check number: [-+]?[0-9]*(.[0-9]*)?([eE][-+]?[0-9]+)?
    size_t i = 0;

    if (i < v.size() && (v[i] == '-' || v[i] == '+'))
        ++i;

    bool hasDigit = false;
    while (i < v.size() && std::isdigit((unsigned char)v[i])) {
        hasDigit = true; ++i;
    }

    if (i < v.size() && v[i] == '.') {
        ++i;
        while (i < v.size() && std::isdigit((unsigned char)v[i])) {
            hasDigit = true; ++i;
        }
    }

    if (i < v.size() && (v[i] == 'e' || v[i] == 'E')) {
        ++i;
        if (i < v.size() && (v[i] == '+' || v[i] == '-'))
            ++i;
        bool expDigit = false;
        while (i < v.size() && std::isdigit((unsigned char)v[i])) {
            expDigit = true; ++i;
        }
        if (!expDigit)
            return false;
    }

    return hasDigit && i == v.size();
}

/*
 map_to_flat_json:
  m - Map of key/value pairs to serialize as a flat JSON object. Keys are
      always emitted as JSON strings (with escaping). Values are emitted as:
        • raw literal if IsJsonLiteral(value) is true (e.g., 123, true, null)
        • quoted/escaped string otherwise.

 Returns: std::string containing a compact JSON object with entries from 'm'
          in unspecified order, without extra whitespace.
*/
std::string map_to_flat_json(const std::unordered_map<std::string, std::string>& m) {
    std::string out;
    out.push_back('{');

    bool first = true;
    for (const auto& [key, value] : m) {
        if (!first) out.push_back(',');
        first = false;

        // Write key
        out.push_back('\"');
        out += JsonEscape(key);
        out.push_back('\"');
        out.push_back(':');

        // Write value (string or literal)
        if (IsJsonLiteral(value)) {
            out += value;            // raw literal: 123, true, null, etc.
        }
        else {
            out.push_back('\"');
            out += JsonEscape(value);
            out.push_back('\"');
        }
    }

    out.push_back('}');
    return out;
}