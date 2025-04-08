import os
import pwn
import json

URL = 'localhost'
PORT = 9001
LOCAL = './main.py'

if 'REMOTE' in os.environ:
    p = pwn.remote (URL, PORT)
else:
    p = pwn.process(LOCAL)

for _ in range(6):
    msg = p.recvline()
    print('got: ', msg)
    msg = b':'.join(msg.split(b':')[1:]).decode().strip().encode()
    print('sending: ', msg)
    p.recvuntil(b':')
    p.sendline(msg)

p.interactive()


p.close()
