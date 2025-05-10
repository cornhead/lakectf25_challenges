import os
import pwn
import json
from Crypto.Protocol.KDF import scrypt
from Crypto.Hash import SHA3_256

URL = 'challs.polygl0ts.ch'
PORT = 9052
LOCAL = './main.py'

if 'REMOTE' in os.environ:
    p = pwn.remote (URL, PORT)
else:
    p = pwn.process(LOCAL)



KDF = lambda mystr : scrypt(mystr, key_len=16, N=2**14, r=8, p=1, salt='LakeCTF25_KDFsalt')

def get_msg(consume_next_prompt=True):
    msg = p.recvline()
    msg = b':'.join(msg.split(b':')[1:]).decode().strip().encode()
    if consume_next_prompt:
        prompt = p.recvuntil(b':')
        # print('prompt: ', prompt.decode())
    return msg

def send_msg(msg):
    p.sendline(msg)


def main():

    for i in range(5):
        msg = get_msg()
        print(i, msg.decode())
        send_msg(msg)

    msg = p.recvline().decode().strip()
    print(msg)
    assert msg == 'Dorothea is happy.'

    p.close()

if __name__ == '__main__':
    main()
