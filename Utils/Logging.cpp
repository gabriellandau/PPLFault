// PPLFault by Gabriel Landau
// https://twitter.com/GabrielLandau

#include <stdio.h>
#include <stdarg.h>
#include <string>
#include "Logging.h"

LogLevel gLogLevel = LogLevel::Info;

void SetLogLevel(LogLevel lvl)
{
    gLogLevel = lvl;
}

void
LogMessage(
    LogLevel level,
    const char* fmt,
    ...)
{
    va_list va;
    int result = 0;
    std::string prefixedFmt;

    const static char* prefixes[] = {
        " [+] ", // Debug
        " [+] ", // Info
        " [?] ", // Warning
        " [!] "  // Error
    };

    if (level < gLogLevel)
    {
        return;
    }

    prefixedFmt = prefixes[(size_t)level] + std::string(fmt) + "\n";

    va_start(va, fmt);

    vprintf(prefixedFmt.c_str(), va);

    va_end(va);

    return;
}
