import os
import pwn
import json

from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES

from aead import CBCMac

URL = 'localhost'
PORT = 9001
LOCAL = './main.py'

if 'REMOTE' in os.environ:
    p = pwn.remote (URL, PORT)
else:
    p = pwn.process(LOCAL)




def ciphertext_to_parts(mybytes):
    N = AES.block_size

    len_ad_bytes = mybytes[-2*N:-1*N]
    try:
        len_ad = int.from_bytes(len_ad_bytes, byteorder='big')*N
    except ValueError:
        return None

    ad, iv, ct, tag = ( \
        mybytes[:len_ad],
        mybytes[len_ad:len_ad+N],
        mybytes[len_ad+N:-2*N],
        mybytes[-N:]
    )

    return ad, iv+ct, len_ad_bytes, tag

def parts_to_ciphertext(ad, iv_ct, len_ad_bytes, tag):
    return ad + iv_ct + len_ad_bytes + tag

def send_parts(ad, iv_ct, len_ad_bytes, tag):
    p.sendline(
        parts_to_ciphertext(
            ad,
            iv_ct,
            len_ad_bytes,
            tag
        ) \
        .hex() \
        .encode()
    )

def decryption_oracle(ad, iv_ct, len_ad_bytes, tag):
    send_parts(ad, iv_ct, len_ad_bytes, tag)

    p.recvline()
    p.recvline()
    msg = pad(bytes.fromhex(p.recvline().decode()), AES.block_size)

    return msg

def get_aes_dec_of_block(block, last_two_ct_blocks):
    '''
    The last two CT blocks are needed so that the padding
    of the PT is correct.
    '''

    assert len(block) == AES.block_size

    ad = b''
    iv = b'\x00'*AES.block_size
    ct = block + last_two_ct_blocks
    len_ad_bytes = b'\x00'*AES.block_size
    tag = b'\x00'*AES.block_size

    msg = decryption_oracle( ad, iv + ct, len_ad_bytes, tag)
    block_dec = msg[:AES.block_size]

    return block_dec


if __name__ == '__main__':
    # Phase 0 some constants and

    order_pt = pad(json.dumps({
        'name': 'Charlie',
        'order': 'A gigantic pizza with lots of pineapples',
        'address': 'Ada Lovelace Street, No 45'
    }).encode(),
    AES.block_size)

    order_pt_target = pad(json.dumps({
        'name': 'Charlie',
        'order': 'A gigantic pizza with lots of pineapples',
        'address': 'Ada Lovelace Street, No 42'
    }).encode(),
    AES.block_size)

    assert len(order_pt) == len(order_pt_target)


    order_ad, order_iv_ct, order_len_ad_bytes, order_tag = ciphertext_to_parts(
        bytes.fromhex(
            p.recvline() \
            .decode() \
            .strip()
        )
    )

    order_pt_new = order_pt
    order_iv_ct_new = order_iv_ct

    while True:
        xor_mask = strxor( order_pt_new , order_pt_target )
        order_iv_ct_new = strxor( order_iv_ct_new , xor_mask + b'\x00'*(len(order_iv_ct_new) - len(xor_mask)) )

        order_pt_new = decryption_oracle(order_ad, order_iv_ct_new, order_len_ad_bytes, order_tag)

        if order_pt_new == order_pt_target:
            break

    assert order_pt_target == decryption_oracle(order_ad, order_iv_ct_new, order_len_ad_bytes, order_tag)

    print('Done modifying ct, now on to forging the tag')

    last_two_ct_blocks = order_iv_ct_new[-2*AES.block_size:]

    to_mac = pad(order_ad[AES.block_size:] + order_pt_target + order_len_ad_bytes, AES.block_size)
    tag = order_tag

    while len(to_mac) > 0:
        tag_previous = tag

        to_mac, block = to_mac[:-AES.block_size], to_mac[-AES.block_size:]
        tag = strxor( get_aes_dec_of_block(tag, last_two_ct_blocks) , block)

    first_ad_block_new = get_aes_dec_of_block(tag, last_two_ct_blocks)
    print('constructed first block of AD')
    order_ad_new = first_ad_block_new + order_ad[AES.block_size:]

    assert len(order_ad_new) == len(order_ad)

    send_parts(
        order_ad_new,
        order_iv_ct_new,
        order_len_ad_bytes,
        order_tag
    )


    p.recvline()
    print(p.recvline().decode())

    p.close()
