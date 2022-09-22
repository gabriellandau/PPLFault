#pragma once

#include <phnt_windows.h>
#include <phnt.h>
#include <string>

bool BuildPayload(
    HANDLE hBenignDll,
    std::string& payloadBuffer);

bool BlessThread(DWORD dwThreadId, bool bFatal);