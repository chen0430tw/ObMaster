#pragma once
#include <Windows.h>
#include <string>
#include <cstdio>

// ─── Minimal JSON helpers ─────────────────────────────────────────────────────
// No external dependencies. Suitable for simple flat/array JSON output.

inline std::string JEscape(const char* s) {
    if (!s) return "null";
    std::string r;
    r.reserve(64);
    r += '"';
    for (const char* p = s; *p; p++) {
        switch (*p) {
            case '"':  r += "\\\""; break;
            case '\\': r += "\\\\"; break;
            case '\n': r += "\\n";  break;
            case '\r': r += "\\r";  break;
            case '\t': r += "\\t";  break;
            default:
                if ((unsigned char)*p < 0x20)
                    r += '?';
                else
                    r += *p;
        }
    }
    r += '"';
    return r;
}

inline std::string JEscape(const wchar_t* s) {
    if (!s) return "null";
    char buf[MAX_PATH * 3]{};
    WideCharToMultiByte(CP_UTF8, 0, s, -1, buf, sizeof(buf) - 1, nullptr, nullptr);
    return JEscape(buf);
}

// Format a kernel address as a JSON hex string "0xFFFF..."
inline std::string JAddr(unsigned long long addr) {
    char buf[32];
    if (addr == 0) return "null";
    sprintf_s(buf, "\"0x%llx\"", addr);
    return buf;
}
