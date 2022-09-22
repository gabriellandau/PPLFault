# PPLFault via localhost SMB

Performs the PPLFault exploit via a localhost SMB server.

Usage:
```
powershell -ex bypass PPLFault-Localhost-SMB.ps1
```

If this machine has not yet run the exploit, the first run will perform some initial setup then prompt to reboot.  Once setup has been completed, re-run the script to perform the exploit.

The included payload runs an infinite loop inside `services.exe` running as `PsProtectedSignerWinTcb-Light`.
