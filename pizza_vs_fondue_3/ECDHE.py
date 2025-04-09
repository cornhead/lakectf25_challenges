from secrets import randbelow
from Crypto.Protocol.KDF import scrypt

import Curve25519

KDF = lambda mystr : scrypt(mystr, key_len=16, N=2**14, r=8, p=1, salt='LakeCTF25_KDFsalt')

class ECDHE():
    def __init__(self):
        self.x = randbelow(int(Curve25519.G.order()))
        self.own_share = self.x * Curve25519.G
        self.other_share = None

    def get_own_share(self):
        return self.own_share

    def set_other_share(self, other_share):
        self.other_pubK = other_share

        if self.other_pubK == Curve25519.zero:
            raise ValueError("Got zero-element as key share")

    def derive_key(self, purpose:str):
        if self.other_pubK == None:
            raise ValueError("Other key share not set yet")

        sharedK = self.x * self.other_pubK
        print(':sharedK:', sharedK)

        sharedK_str = str(sharedK) + purpose

        K = KDF(sharedK_str)

        return K

