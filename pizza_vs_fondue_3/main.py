#!/usr/bin/python3
import os
import sys

import secrets
from Crypto.Hash import SHA3_256
from Crypto.Hash import KMAC256

import Curve25519
from ECDHE import *
from ECElGamal import *
from util import *

flag = os.getenv('FLAG', 'CTF{dummyflag}')

class PKI(dict):
    def __init__(self):
        super().__init__()

    def __setitem__(self, name, pubK):
        if name in super().keys():
            print('PKI: Username already taken')
            return
        else:
            super().__setitem__(name, pubK)

    def __getitem__(self, name):
        if name not in super().keys():
            print(f'PKI: Unknown name {name}')
            return
        else:
            return super().__getitem__(name)

    def register(self, name, pubK):
        self[name] = pubK

    def get(self, name):
        return self[name]

class FondueRestaurantWebsite:
    def __init__(self, PKI):
        self.elgamal = ECElGamal()
        PKI.register('FRW', self.elgamal.pubK)
        self.PKI = PKI
        self.K_mac = secrets.token_bytes(32)

        self.connection_state = {}

    def get_voucher_1(self, username):
        if username not in self.PKI:
            self._send_msg(username, 'User not found')
            return

        user_pubK = self.PKI.get(username)

        self.connection_state['username'] = username
        self.connection_state['user_pubK'] = user_pubK

        other_elgamal = ECElGamal(pubK=user_pubK)
        self.connection_state['other_elgamal'] = other_elgamal

        ecdhe = ECDHE()
        own_share = ecdhe.get_own_share()
        own_share_enc = other_elgamal.enc(own_share)
        self.connection_state['ecdhe'] = ecdhe

        self._send_msg(username, ECElGamal.serialize_ct(own_share_enc))
        return

    def get_voucher_2(self):
        username = self.connection_state['username']

        while True:
            other_share_enc_str = self._recv_msg(username)

            try:
                other_share_enc = ECElGamal.deserialize_ct(other_share_enc_str)
            except ValueError as e:
                print(e)
                continue

            try:
                other_share = self.elgamal.dec(other_share_enc)
            except Exception as e:
                print(e)
                continue

            break

        ecdhe = self.connection_state['ecdhe']
        ecdhe.set_other_share(other_share)
        K = ecdhe.derive_key(purpose='encryption')
        self.connection_state['K'] = K

        msg = b'Please tell me the hash of your desired redemption code'
        ct_str = AES_GCM_enc(K, msg)
        self._send_msg(username, ct_str)
        return

    def get_voucher_3(self):
        username = self.connection_state['username']
        K = self.connection_state['K']

        while True:
            H_redemptioncode_enc_str = self._recv_msg(username)

            try:
                H_redemptioncode = AES_GCM_dec(K, H_redemptioncode_enc_str)
            except Exception as e:
                print(e)
                continue

            break

        msg = b'This is a gift voucher for one free fondue... a foucher. To redeem, provide pre-image of: ' + H_redemptioncode

        mac = KMAC256.new(key=self.K_mac, mac_len=32)
        mac.update(msg)
        tag = mac.digest()

        j = json.dumps( {'msg':msg.decode(), 'tag':tag.hex()})

        ct = AES_GCM_enc(K, j.encode())
        self._send_msg(username, ct)
        return

    def redeem_voucher(self):
        while True:
            msg_str = self._recv_msg('<Unknown User>')

            try:
                msg_json = json.loads(msg_str)
            except Exception as e:
                print(e)
                continue

            break

        if not msg_json['msg'].startswith('This is a gift voucher for one free fondue... a foucher. To redeem, provide pre-image of: '):
            print('Failed to redeem voucher: Message has not the expected format')
            return

        mac = KMAC256.new(key=self.K_mac, mac_len=32)
        mac.update(msg_json['msg'].encode())
        try:
            mac.verify(bytes.fromhex(msg_json['tag']))
        except ValueError:
            print("Failed to redeem voucher: Voucher is un-authentic")
            return

        H = bytes.fromhex(msg_json['msg'][-64:])

        token = bytes.fromhex(msg_json['preimage'])
        sha = SHA3_256.new(data=token)
        H_prime = sha.digest()

        if H != H_prime:
            print("Failed to redeem voucher: Preimage incorrect")
            return

        self._send_msg('<Unknown User>', 'Here is your free fondue: ' + flag)



    def _send_msg(self, username, msg):
        print(f'FRW->{username}: ' + msg)

    def _recv_msg(self, username):
        msg = input(f'FRW<-{username}: ')
        return msg



class Bob:
    def __init__(self, server, PKI):
        self.username = 'Bob'
        self.server = server
        self.elgamal = ECElGamal()
        PKI.register(self.username, self.elgamal.pubK)
        self.PKI = PKI

    def run(self):

        self.server.get_voucher_1(self.username)

        while True:
            other_share_enc_str = self._recv_msg()

            try:
                other_share_enc = ECElGamal.deserialize_ct(other_share_enc_str)
            except ValueError as e:
                print('Bob couldn\'t parse server share: ' + str(e))
                continue

            try:
                other_share = self.elgamal.dec(other_share_enc)
            except Exception as e:
                print('Bob cound\'t decrypt server share: ' + str(e))
                continue

            break

        ecdhe = ECDHE()
        ecdhe.set_other_share(other_share)
        K = ecdhe.derive_key(purpose='encryption')

        server_pubK = self.PKI.get('FRW')
        own_share = ecdhe.own_share
        server_elgamal = ECElGamal(pubK=server_pubK)
        own_share_enc = server_elgamal.enc(own_share)

        self._send_msg(ECElGamal.serialize_ct(own_share_enc))

        self.server.get_voucher_2()

        while True:
            ct_str = self._recv_msg()

            try:
                msg = AES_GCM_dec(K, ct_str)
            except Exception as e:
                print('Bob cound\'t decrypt server first encrypted message: ' + str(e))
                continue

            break

        self.token = secrets.token_bytes(16)

        sha = SHA3_256.new(data=self.token)
        H = sha.digest()

        ct_str = AES_GCM_enc(K, H.hex().encode())
        self._send_msg(ct_str)

        self.server.get_voucher_3()

        while True:
            ct_str = self._recv_msg()

            try:
                msg = AES_GCM_dec(K, ct_str)
            except Exception as e:
                print('Bob cound\'t decrypt server first encrypted message: ' + str(e))
                continue

            try:
                msg_json = json.loads(msg)
            except Exception as e:
                print('Bob cound\'t parse voucher as JSON: ' + str(e))
                continue

            break

        self.voucher = msg_json

    # def redeem_voucher(self):
    #     msg = self.voucher
    #     msg['preimage'] = self.token.hex()
    #
    #     self._send_msg(json.dumps(msg))
    #
    #     self.server.redeem_voucher()



    def _send_msg(self, msg):
        print(f'{self.username}->FRW: ' + msg)

    def _recv_msg(self):
        msg = input(f'{self.username}<-FRW: ')
        return msg


def main():
    pki = PKI()

    frw = FondueRestaurantWebsite(pki)
    bob = Bob(frw, pki)

    bob.run()

    frw.redeem_voucher()

if __name__ == '__main__':
    main()
