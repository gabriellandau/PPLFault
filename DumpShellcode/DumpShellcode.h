#pragma once

#include <phnt_windows.h>
#include <phnt.h>
#include <dbghelp.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef NTSTATUS (NTAPI * RtlAdjustPrivilege_t)(
    DWORD privilege,
    BOOL bEnablePrivilege,
    BOOL IsThreadPrivilege,
    PDWORD PreviousValue);

typedef HMODULE(WINAPI* LoadLibraryW_t)(
    LPCWSTR lpLibFileName
    );

typedef FARPROC(WINAPI* GetProcAddress_t)(
    HMODULE hModule,
    LPCSTR  lpProcName
    );

typedef HANDLE(WINAPI* OpenProcess_t)(
    DWORD dwDesiredAccess,
    BOOL  bInheritHandle,
    DWORD dwProcessId
    );

typedef HANDLE(WINAPI* CreateFileW_t)(
    LPCWSTR               lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
    );

typedef BOOL(WINAPI* TerminateProcess_t)(
    HANDLE hProcess,
    UINT   uExitCode
    );

typedef BOOL(WINAPI* MiniDumpWriteDump_t)(
    HANDLE                            hProcess,
    DWORD                             ProcessId,
    HANDLE                            hFile,
    MINIDUMP_TYPE                     DumpType,
    PMINIDUMP_EXCEPTION_INFORMATION   ExceptionParam,
    PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
    PMINIDUMP_CALLBACK_INFORMATION    CallbackParam
    );

#define MAGIC1 0x1BADC0D3
#define MAGIC2 0xDEADBEEF

typedef struct _SHELLCODE_PARAMS
{
    DWORD magic1;
    DWORD magic2;

    // User params
    DWORD dwTargetProcessId;
    WCHAR dumpPath[MAX_PATH];

    // Strings (so we don't have to embed them in shellcode)
    CHAR szMiniDumpWriteDump[20]; // "MiniDumpWriteDump"
    WCHAR szDbgHelpDll[12]; // L"Dbghelp.dll"

    // IAT
    LoadLibraryW_t pLoadLibraryW;
    GetProcAddress_t pGetProcAddress;
    OpenProcess_t pOpenProcess;
    CreateFileW_t pCreateFileW;
    TerminateProcess_t pTerminateProcess;
    RtlAdjustPrivilege_t pRtlAdjustPrivilege;
} SHELLCODE_PARAMS, * PSHELLCODE_PARAMS;

#ifdef __cplusplus
} // extern "C"
#endif
