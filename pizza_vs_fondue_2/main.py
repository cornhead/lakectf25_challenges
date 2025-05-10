#!/usr/local/bin/python3 -u

import random
import os
import sys
import json
import time

from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

from aead import AEAD

flag = os.getenv('FLAG', 'EPFL{dummyflag}')

class SecurePizzaDeliveryService:
    def __init__(self, key):
        self.key = key

        # For collection of user metadata.
        # (Metadata is not so privacy sensitive, right?)
        self.metadata_storage = list()

    def order(self, order_ct:bytes):
        aead = AEAD(self.key)
        try:
            vrf, metadata, order_pt = aead.dec(order_ct)
        except ValueError:
            print(
                'Internal Server Error' \
                '(maybe something with padding, but who cares about padding)'\
            )
            return

        if not vrf:
            print('ALERT: It looks like someone wanted to tamper with your ciphertext.')
            print('The intruder wanted to inject the following message instead of your actual order [hex]:')
            print(order_pt.hex())
            return

        self.metadata_storage.append(metadata)

        try:
            order = json.loads(order_pt.decode())
        except ValueError:
            print('An Error occurred: We could not parse your order as JSON')

        if not all([keyword in order for keyword in ['name', 'order', 'address']]):
            print('Your order is incomplete. It must contain at least the fields "name", "order" and "address".')
            return

        with open('/dev/null', 'w') as trashbin:
            trashbin.write(str(order))

        print("Thanks! Your secret order is being processed.")

        if order['address'] == 'Ada Lovelace Street, No 42':
            print(flag)


class Charlie:
    def __init__(self, key):
        self.key = key

    def post_order(self):
        order = json.dumps({
            'name': 'Charlie',
            'order': 'A gigantic pizza with lots of pineapples',
            'address': 'Ada Lovelace Street, No 45',
        })


        metadata = json.dumps({
            'time-stamp' : time.time(),
        })

        aead = AEAD(key)
        order_ct = aead.enc(pad(metadata.encode(), 16), order.encode())

        return order_ct


if __name__ == '__main__':

    key = get_random_bytes(16)

    spds = SecurePizzaDeliveryService(key)
    charlie = Charlie(key)

    order_ct = charlie.post_order()
    print(order_ct.hex())

    while True:
        order_ct_str = input('[Your encrypted order in hex]: ')
        try:
            order_ct = bytes.fromhex(order_ct_str)
        except ValueError:
            print('Could not parse your order as hex')
            continue

        time.sleep(0.1)

        spds.order(order_ct)
