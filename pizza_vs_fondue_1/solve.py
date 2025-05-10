#!/usr/bin/python3

import os
import pwn
from Crypto.Util.number import bytes_to_long

from HCom import HCom

URL = 'challs.polygl0ts.ch'
PORT = 9050
LOCAL = './main.py'

if 'REMOTE' in os.environ:
    p = pwn.remote (URL, PORT)
else:
    p = pwn.process(LOCAL)


if __name__ == '__main__':
    m_false = 'False'
    m_true = 'Fals'

    r_false = bytes_to_long(b'1337')
    r_true = bytes_to_long(b'e1337')

    C = HCom.com(m_false, r_false)

    assert HCom.vrf(m_false, r_false, C) and HCom.vrf(m_true, r_true, C)

    print(p.recvuntil(b':').decode())
    p.sendline(C.hex().encode())

    alices_coin = ('True' in p.recvline().decode())

    if alices_coin:
        p.sendline(m_false.encode()+b','+str(r_false).encode())
        p.sendline(m_true.encode()+b','+str(r_true).encode())
    else:
        p.sendline(m_true.encode()+b','+str(r_true).encode())
        p.sendline(m_false.encode()+b','+str(r_false).encode())


    print(p.recvall().decode())

    p.close()
