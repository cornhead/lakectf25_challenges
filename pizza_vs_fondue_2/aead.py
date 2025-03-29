from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

N = AES.block_size

class CBCMac:
    def __init__(self, key:bytes):
        self.key=key

    def tag(self, msg:bytes) -> bytes:
        cipher = AES.new(self.key, mode=AES.MODE_CBC, iv=b'\x00'*N)
        tag = cipher.encrypt(pad(msg, N))[-N:]
        return tag

    def vrf(self, msg:bytes, tag:bytes) -> bool:
        tag_prime = self.tag(msg)
        return tag_prime == tag

class AEAD:
    '''
    This class provides a scheme for authenticated
    encryption with associated data (AEAD).

    Since everything is based on AES, our scheme
    has military-grade security.
    '''

    def __init__(self, key:bytes):
        assert len(key) % N == 0
        self.key = key

    def enc(self, ad:bytes, msg:bytes) -> bytes:
        '''
        Encryption.
        Takes the associated data and the message,
        encrypts the message and then adds integrity
        protection to everything.
        '''

        assert len(ad) % N == 0 # TODO: In future versions, also pad AD

        msg_padded = pad(msg, N)

        aes = AES.new(self.key, mode=AES.MODE_CBC)
        iv = aes.iv
        ct = aes.encrypt(msg_padded)

        # block length as bytes
        len_ad_bytes = (len(ad)//N) \
            .to_bytes(N)

        cbcmac = CBCMac(self.key)
        tag = cbcmac.tag(
            ad + \
            msg_padded + \
            len_ad_bytes \
        )

        return ad+iv+ct+len_ad_bytes+tag

    def dec(self, mybytes:bytes) -> tuple[bool, bytes]:
        '''
        Decryption.
        Takes a ciphertext as obtained by the
        above encryption, checks its integrity,
        decrypts it and returns the associated
        data and the message.

        For simplicity, there is is no error handling.
        Error handling is the responsibility of the user.
        '''

        len_ad_bytes = mybytes[-2*N:-1*N]
        len_ad = int.from_bytes(len_ad_bytes, byteorder='big')*N

        ad, iv, ct, tag = ( \
            mybytes[:len_ad],
            mybytes[len_ad:len_ad+N],
            mybytes[len_ad+N:-2*N],
            mybytes[-N:]
        )

        aes = AES.new(self.key, mode=AES.MODE_CBC, iv=iv)
        msg_padded = aes.decrypt(ct)

        cbcmac = CBCMac(self.key)
        vrf = cbcmac.vrf(
            ad + \
            msg_padded + \
            len_ad_bytes, \
            tag
        )

        msg = unpad(msg_padded, N)

        return (vrf, ad, msg)

