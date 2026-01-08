#pragma once

#include <string>

#ifdef _WIN32
#include <windows.h>
#include <memory>
#endif

inline std::string ToUtf8(const std::wstring& ws)
{
#ifdef _WIN32
    if (ws.empty()) return {};
    int size_needed = ::WideCharToMultiByte(CP_UTF8, 0, ws.data(), (int)ws.size(), NULL, 0, NULL, NULL);
    if (size_needed <= 0) return {};
    std::string result;
    result.resize(size_needed);
    ::WideCharToMultiByte(CP_UTF8, 0, ws.data(), (int)ws.size(), &result[0], size_needed, NULL, NULL);
    return result;
#else
    // Portable fallback (may be locale dependent)
    std::string s(ws.begin(), ws.end());
    return s;
#endif
}
