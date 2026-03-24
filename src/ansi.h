#pragma once
#include <Windows.h>
#include <io.h>

// ─── ANSI terminal color support ─────────────────────────────────────────────
// Call AnsiInit() once at startup. Color macros expand to empty strings when
// stdout is not a terminal or VT processing could not be enabled.

extern bool g_ansiEnabled;

inline void AnsiInit() {
    if (_isatty(_fileno(stdout)) == 0) return;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode))
        if (SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
            g_ansiEnabled = true;
}

// Foreground colors (bright variants for readability on dark terminals)
#define A_RESET  (g_ansiEnabled ? "\033[0m"   : "")
#define A_BOLD   (g_ansiEnabled ? "\033[1m"   : "")
#define A_DIM    (g_ansiEnabled ? "\033[2m"   : "")
#define A_RED    (g_ansiEnabled ? "\033[91m"  : "")   // critical / error
#define A_GREEN  (g_ansiEnabled ? "\033[92m"  : "")   // success
#define A_YELLOW (g_ansiEnabled ? "\033[93m"  : "")   // warning / active
#define A_BLUE   (g_ansiEnabled ? "\033[94m"  : "")
#define A_CYAN   (g_ansiEnabled ? "\033[96m"  : "")   // system / trusted
#define A_WHITE  (g_ansiEnabled ? "\033[97m"  : "")
