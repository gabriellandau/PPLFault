#pragma once

#include <phnt_windows.h>
#include <string>

bool BuildPayload(
    HANDLE hBenignDll,
    std::string& payloadBuffer,
    DWORD dwTargetProcessId,
    PCWCHAR pDumpPath);
