from secrets import randbelow
from Crypto.Protocol.KDF import scrypt

import Curve25519

KDF = lambda mystr : scrypt(mystr, 16)

class ECDH():
    def setup():
        privK = randbelow(Curve25519.G.order())
        return privK

    def __init__(self, privK):
        self.privK = privK
        self.other_pubK = None

    def send_message(self):
        pubK = self.privK * Curve25519.G
        return pubK

    def recv_message(self, msg):
        # TODO: parse from json
        self.other_pubK = Curve25519.E([x,y])

        if self.other_pubK == Curve25519.one:
            raise ValueError

    def derive_key(self):
        if self.other_pubK == None:
            raise ValueError

        sharedK = self.privK * self.other_pubK

        sharedK_str = str(sharedK.xy())

        K = KDF(sharedK_str)

