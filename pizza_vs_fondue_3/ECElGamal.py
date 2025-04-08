from secrets import randbelow
from Crypto.Protocol.KDF import scrypt
import json

import Curve25519
from util import ec_point_from_dict, ec_point_to_dict

KDF = lambda mystr : scrypt(mystr)

class ECElGamal():
    def setup():
        privK = randbelow(int(Curve25519.G.order()))
        return privK

    def __init__(self, pubK=None, privK=None):
        if privK != None:
            self.privK = privK
            self.pubK = self.privK * Curve25519.G
        elif pubK != None:
            self.privK = None
            self.pubK = pubK
        else:
            self.privK = ECElGamal.setup()
            self.pubK = self.privK * Curve25519.G

    def get_pubK(self):
        return self.pubK

    def enc(self, m):
        '''
        Encrypts message `m` (EC group elemtn)
        '''

        r = randbelow(int(Curve25519.G.order()))

        c_1 = r * Curve25519.G
        c_2 = m + (r * self.pubK)

        return (c_1, c_2)


    def dec(self, c):
        assert self.privK != None

        c_1, c_2 = c

        g_x_r = self.privK * c_1

        m = c_2 - g_x_r

        return m

    def serialize_ct(c):
        c_1, c_2 = c
        return json.dumps({'c_1': ec_point_to_dict(c_1), 'c_2': ec_point_to_dict(c_2)})

    def deserialize_ct(mystr):
        d = json.loads(mystr)

        if 'c_1' not in d or 'c_2' not in d:
            raise ValueError('Error while deserializing ciphertext: ciphertext needs to consist of "c_1" and "c_2"')

        c_1 = ec_point_from_dict(d['c_1'])
        c_2 = ec_point_from_dict(d['c_2'])

        return (c_1, c_2)


