#pragma once

#include <ntifs.h>

#define PHNT_MODE 0
#pragma warning(push)
#pragma warning(disable: 4201) // nonstandard extension used: nameless struct/union
#include <phnt.h>
//#include <phnt_windows.h>
#pragma warning(pop)

extern "C" {

NTSYSAPI
NTSTATUS
NTAPI
ZwSetInformationProcess(
	IN HANDLE               ProcessHandle,
	IN PROCESSINFOCLASS     ProcessInformationClass,
	IN PVOID                ProcessInformation,
	IN ULONG                ProcessInformationLength);

NTSTATUS NTAPI ZwQueryInformationProcess(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
);

#pragma warning(push)
#pragma warning(disable: 4201) // warning C4201: nonstandard extension used: nameless struct/union
#pragma warning(disable: 4214) // warning C4214: nonstandard extension used: bit field types other than int

// From https://docs.microsoft.com/en-us/windows/win32/procthread/zwqueryinformationprocess
typedef enum _PS_PROTECTED_TYPE {
    PsProtectedTypeNone = 0,
    PsProtectedTypeProtectedLight = 1,
    PsProtectedTypeProtected = 2
} PS_PROTECTED_TYPE, * PPS_PROTECTED_TYPE;

typedef enum _PS_PROTECTED_SIGNER {
    PsProtectedSignerNone = 0,
    PsProtectedSignerAuthenticode,
    PsProtectedSignerCodeGen,
    PsProtectedSignerAntimalware,
    PsProtectedSignerLsa,
    PsProtectedSignerWindows,
    PsProtectedSignerWinTcb,
    PsProtectedSignerWinSystem,
    PsProtectedSignerApp,
    PsProtectedSignerMax
} PS_PROTECTED_SIGNER, * PPS_PROTECTED_SIGNER;

typedef struct _PS_PROTECTION {
    union {
        UCHAR Level;
        struct {
            UCHAR Type : 3;
            UCHAR Audit : 1;                  // Reserved
            UCHAR Signer : 4;
        };
    };
} PS_PROTECTION, * PPS_PROTECTION;

// private
typedef struct _PROCESS_MITIGATION_POLICY_INFORMATION
{
    PROCESS_MITIGATION_POLICY Policy;
    union
    {
        PROCESS_MITIGATION_ASLR_POLICY ASLRPolicy;
        PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY StrictHandleCheckPolicy;
        PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY SystemCallDisablePolicy;
        PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY ExtensionPointDisablePolicy;
        PROCESS_MITIGATION_DYNAMIC_CODE_POLICY DynamicCodePolicy;
        PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY ControlFlowGuardPolicy;
        PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY SignaturePolicy;
        PROCESS_MITIGATION_FONT_DISABLE_POLICY FontDisablePolicy;
        PROCESS_MITIGATION_IMAGE_LOAD_POLICY ImageLoadPolicy;
        PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY SystemCallFilterPolicy;
        PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY PayloadRestrictionPolicy;
        PROCESS_MITIGATION_CHILD_PROCESS_POLICY ChildProcessPolicy;
        PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY SideChannelIsolationPolicy;
        PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY UserShadowStackPolicy;
        PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY RedirectionTrustPolicy;
    };
} PROCESS_MITIGATION_POLICY_INFORMATION, * PPROCESS_MITIGATION_POLICY_INFORMATION;

#pragma warning(pop)

}