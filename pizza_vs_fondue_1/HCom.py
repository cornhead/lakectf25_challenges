from Crypto.Hash import SHA3_512
from Crypto.Util.number import long_to_bytes, bytes_to_long

class HCom:
    '''
    A commitment scheme based on a cryptographic hash function
    '''

    def com(msg:str, r:int) -> bytes:
        '''
        Takes a message as string and a random integer
        and returns a commitment to the message as bytes.
        '''

        msg_bytes = msg.encode()
        r_bytes = long_to_bytes(r)

        H = SHA3_512.new()
        H.update(msg_bytes)
        H.update(r_bytes)

        return H.digest()

    def vrf(msg:str, r:int, C:bytes) -> bool:
        '''
        Verifies the opening of a commitment.
        Takes the opening information (message and randomness)
        and the commitment and returns the verification result.
        '''

        return HCom.com(msg, r) == C
