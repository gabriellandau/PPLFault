
#include <phnt_windows.h>
#include <phnt.h>
#include <string>

// Finds the address within buf of the image entrypoint 
PVOID FindEntrypointVA(const std::string& buf);

// Build a payload that consists of the given benign DLL with its entrypoint overwritten by our shellcode
bool WriteShellcode(LPCWSTR lpResourceName, PVOID pBuf, SIZE_T maxLength, DWORD& bytesWritten);
