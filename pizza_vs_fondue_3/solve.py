#!/usr/bin/python3

import os
import sys
import pwn
import json
from Crypto.Protocol.KDF import scrypt
from Crypto.Hash import SHA3_256

from util import *
import Curve25519

URL = 'challs.polygl0ts.ch'
PORT = 9052
LOCAL = './main.py'

if 'REMOTE' in os.environ:
    p = pwn.remote (URL, PORT)
else:
    p = pwn.process(LOCAL)



KDF = lambda mystr : scrypt(mystr, key_len=16, N=2**14, r=8, p=1, salt='LakeCTF25_KDFsalt')

multiply_by_factor = Curve25519.q

def get_msg(consume_next_prompt=True):
    msg = p.recvline()

    if b'Traceback' in msg:
        print('Error:')
        print(p.recvall().decode())
        sys.exit(1)

    msg = b':'.join(msg.split(b':')[1:]).decode().strip().encode()
    if consume_next_prompt:
        prompt = p.recvuntil(b':')
        # print('prompt: ', prompt.decode())
    return msg

def send_msg(msg):
    p.sendline(msg)


def recv_double_elgamal_and_send(identifier):
    msg = get_msg()
    msg = json.loads(msg.decode())
    print(f'{identifier}:', msg)
    p1, p2 = [ ec_point_from_dict(msg[k]) for k in msg.keys()]
    msg_prime = { k: ec_point_to_dict(multiply_by_factor*p) for k, p in zip(msg.keys(), [p1, p2])}
    print(f'{identifier}_prime: ', msg_prime)
    send_msg(json.dumps(msg_prime).encode())

def main():

    recv_double_elgamal_and_send('msg1')
    recv_double_elgamal_and_send('msg2')

    msg3 = get_msg()
    print('msg3', msg3)


    roots = Curve25519.E.torsion_polynomial(4).roots(multiplicities=True)
    print(roots)
    for r, m in roots:
        if r != 0:
            try:
                r = Curve25519.E.lift_x(r)
                print('Lifted x successfully:', r)
            except Exception as e:
                print('failed to lift x:', e)
                continue

            for i in range(4):
                sharedK = i*r
                print(sharedK)
                try:
                    sharedK_str = str(sharedK) + 'encryption'
                except Exception as e:
                    print('couln\'t convert shared key to string:', e)
                    continue
                K = KDF(sharedK_str)

                try:
                    AES_GCM_dec(K, msg3)
                    print("correct key!")
                    break
                except Exception as e:
                    print('decryption failed:', e)

    send_msg(msg3)


    print('bobs hashed token: ↓')
    msg4 = get_msg()
    print(msg4)

    token = b'this_is_my_secret_token'
    sha = SHA3_256.new(data=token)
    H = sha.digest()
    ct_str = AES_GCM_enc(K, H.hex().encode())
    send_msg(ct_str.encode())

    print('voucher: ↓')
    msg5 = get_msg()
    print(msg5)
    send_msg(msg5)

    msg = p.recvline().decode().strip()
    print(msg)
    assert msg == 'Dorothea is happy.'
    # Dorothea terminates happily

    msg5 = AES_GCM_dec(K, msg5)
    msg5 = json.loads(msg5.decode())

    redeemmessage = msg5
    redeemmessage['preimage'] = token.hex()
    # p.recvline() # to consume prompt
    send_msg(json.dumps(redeemmessage).encode())

    print('flag: ↓')
    print(get_msg(consume_next_prompt=False).decode())

    p.close()

if __name__ == '__main__':
    main()
