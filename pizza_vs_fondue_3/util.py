import json
from Crypto.Cipher import AES

import Curve25519

def ec_point_to_dict(p):
    if p == Curve25519.zero:
        return {'iszero': True}

    px, py = p.xy()
    return {'iszero': False, 'coordinates': [int(px), int(py)]}

def serialize_ec_point(p):
    return json.dumps(ec_point_to_dict(p))

def ec_point_from_dict(d):
    if 'iszero' not in d.keys():
        raise ValueError("Error while desirializing EC point: 'iszero' not in JSON object")

    if d['iszero']:
        return Curve25519.zero

    if 'coordinates' not in d.keys():
        raise ValueError("Error while desirializing EC point: 'coordinates' not in JSON object of non-zero point")

    if not isinstance(d['coordinates'], list):
        raise ValueError("Error while desirializing EC point: 'coordinates' needs to be a list")

    if len(d['coordinates']) != 2:
        raise ValueError(f"Error while desirializing EC point: 'coordinates' needs to of of length 2, got {len(j['coordinates'])}")

    return Curve25519.E(d['coordinates'])

def deserialize_ec_point(mystr):
    d = json.loads(mystr)
    return ec_point_from_dict(d)

def AES_GCM_enc(key, msg):
    aes = AES.new(key, mode=AES.MODE_GCM)
    ciphertext, tag = aes.encrypt_and_digest(msg)
    json_k = [ 'nonce', 'ciphertext', 'tag' ]
    json_v = [ x.hex() for x in (aes.nonce, ciphertext, tag) ]
    result = json.dumps(dict(zip(json_k, json_v)))
    return result

def AES_GCM_dec(key, ct_str):
    ct = json.loads(ct_str)
    json_k = [ 'nonce', 'ciphertext', 'tag' ]
    jv = {k: bytes.fromhex(ct[k]) for k in json_k}

    aes = AES.new(key, AES.MODE_GCM, nonce=jv['nonce'])
    msg = aes.decrypt_and_verify(jv['ciphertext'], jv['tag'])
    return msg
