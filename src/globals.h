#pragma once

// Global flags set by main() before command dispatch
extern bool g_jsonMode;     // /json  — output machine-readable JSON instead of text
extern bool g_quiet;        // /quiet — suppress banner (for scripting / agent use)
extern bool g_ansiEnabled;  // true when VT processing is active on stdout
extern bool g_debug;        // /debug — verbose diagnostics (export scan, slot reads, etc.)
