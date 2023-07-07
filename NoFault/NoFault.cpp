#include "NoFault.h"

// Define _ALLOW_UNLOAD if you want to allow this driver to be unloaded
// This allows malware to unload this driver and exploit previously-protected systems
// If unloads are not allowed, the system must be rebooted to remove the protection provided by this driver
#ifdef _DEBUG
#define _ALLOW_UNLOAD
#else
#define _ALLOW_UNLOAD
#endif // _DEBUG



// Applies BlockRemoteImageLoads mitigation to the given process
NTSTATUS HardenProcess(PEPROCESS pProcess, HANDLE hProcess)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PROCESS_MITIGATION_POLICY_INFORMATION policy;
	KAPC_STATE apcState = { 0, };

	RtlZeroMemory(&policy, sizeof(policy));

	// First pull existing policy
	policy.Policy = ProcessImageLoadPolicy;
	ntStatus = ZwQueryInformationProcess(hProcess, ProcessMitigationPolicy, &policy, sizeof(policy), NULL);
	if (!NT_SUCCESS(ntStatus))
	{
		goto Cleanup;
	}

	// The attack uses the SMB redirector
	policy.ImageLoadPolicy.NoRemoteImages = TRUE;

	// ZwSetInformationProcess(ProcessMitigationPolicy) requires ZwCurrentProcess(), so briefly jump into the remote process
	KeStackAttachProcess(pProcess, &apcState);
	{
		ntStatus = ZwSetInformationProcess(ZwCurrentProcess(), ProcessMitigationPolicy, &policy, sizeof(policy));
	}
	KeUnstackDetachProcess(&apcState);

Cleanup:
	return ntStatus;
}

// Is the current process *-Full or WinTcb-Light?
BOOLEAN IsCurrentProcessFullPPOrWinTcbLight()
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	BOOLEAN bResult = FALSE;
	PS_PROTECTION protection = { 0, };

	ntStatus = ZwQueryInformationProcess(ZwCurrentProcess(), ProcessProtectionInformation, &protection, sizeof(protection), NULL);
	if (!NT_SUCCESS(ntStatus))
	{
		goto Cleanup;
	}

	// Full Protected Processes
	if (PsProtectedTypeProtected == protection.Type)
	{
		bResult = TRUE;
		goto Cleanup;
	}

	// WinTcb-Light
	if ((PsProtectedTypeProtectedLight == protection.Type) &&
		(PsProtectedSignerWinTcb == protection.Signer))
	{
		bResult = TRUE;
		goto Cleanup;
	}

Cleanup:
	return bResult;
}

// Returns whether the given process should have the BlockRemoteImageLoads mitigation policy applied
BOOLEAN ShouldHardenProcess(HANDLE hProcess)
{
	BOOLEAN bResult = FALSE;
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PS_PROTECTION protection = { 0, };

	// Do not interfere with actions taken by core Windows processes
	if (IsCurrentProcessFullPPOrWinTcbLight())
	{
		goto Cleanup;
	}

	// Determine protection status
	ntStatus = ZwQueryInformationProcess(hProcess, ProcessProtectionInformation, &protection, sizeof(protection), NULL);
	if (!NT_SUCCESS(ntStatus))
	{
		goto Cleanup;
	}

	// Only applies to PPL.  I could not reproduce this on PP.
	if (PsProtectedTypeProtectedLight != protection.Type) 
	{
		goto Cleanup;
	}

	switch (protection.Signer)
	{
	case PsProtectedSignerCodeGen:
	case PsProtectedSignerLsa:
	case PsProtectedSignerWindows:
	case PsProtectedSignerWinTcb:
	case PsProtectedSignerWinSystem:
	case PsProtectedSignerAntimalware:
		// Note: Applying this to PsProtectedSignerAntimalware is debatable
		// External vendors can run code as PsProtectedSignerAntimalware-Light, so enabling this here risks breaking their software
		// We could enable it by default, and allow them to opt-out via SetProcessMitigationPolicy
		bResult = TRUE;
	default:
		break;
	}

Cleanup:
	return bResult;
}

void CreateProcessNotifyRoutine(
	PEPROCESS pProcess,
	HANDLE ProcessId,
	PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
	HANDLE hProcess = NULL;
	NTSTATUS ntStatus = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(ProcessId);

	if (!CreateInfo)
	{
		// Process termination
		goto Cleanup;
	}

	// PEPROCESS -> HANDLE
	ntStatus = ObOpenObjectByPointer(pProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &hProcess);
	if (!NT_SUCCESS(ntStatus))
	{
		goto Cleanup;
	}

	if (ShouldHardenProcess(hProcess))
	{
		(void)HardenProcess(pProcess, hProcess);
	}

Cleanup:
	if (hProcess)
	{
		ZwClose(hProcess);
	}

	return;
}

void
DriverUnload(
	IN PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	(void)PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, TRUE);
}

EXTERN_C
NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT  DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	ntStatus = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, FALSE);

#ifdef _ALLOW_UNLOAD
	DriverObject->DriverUnload = DriverUnload;
#endif // _ALLOW_UNLOAD

	return ntStatus;
}
