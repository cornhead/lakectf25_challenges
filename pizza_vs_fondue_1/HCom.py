from Crypto.Hash import SHA3_512
from Crypto.Util.number import long_to_bytes, bytes_to_long

class HCom:
    def com(msg:str, r:int) -> bytes:
        msg_bytes = msg.encode()
        r_bytes = long_to_bytes(r)

        H = SHA3_512.new()
        H.update(msg_bytes)
        H.update(r_bytes)

        return H.digest()

    def vrf(msg:str, r:int, C:bytes) -> bool:
        return HCom.com(msg, r) == C
