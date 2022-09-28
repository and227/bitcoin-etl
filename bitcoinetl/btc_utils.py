import math
from decimal import Decimal
import hashlib
import base58


def bitcoin_to_satoshi(bitcoin_value):
    if bitcoin_value is None:
        return bitcoin_value

    if isinstance(bitcoin_value, Decimal):
        return int(bitcoin_value * (Decimal(10) ** 8).to_integral_value())
    else:
        return int(bitcoin_value * math.pow(10, 8))


def _hash160(hex_str):
    sha = hashlib.sha256()
    rip = hashlib.new('ripemd160')
    sha.update(hex_str)
    rip.update(sha.digest())
    return rip.hexdigest()  # .hexdigest() is hex ASCII


def decode_address_from_pubkey(pubkey: str, compress_pubkey: bool = False) -> str:
    if compress_pubkey:
        if ord(bytearray.fromhex(pubkey[-2:])) % 2 == 0:
            pubkey_compressed = '02'
        else:
            pubkey_compressed = '03'
        pubkey_compressed += pubkey[2:66]
        hex_str = bytearray.fromhex(pubkey_compressed)
    else:
        hex_str = bytearray.fromhex(pubkey)

    key_hash = '00' + _hash160(hex_str)

    sha = hashlib.sha256()
    sha.update(bytearray.fromhex(key_hash))
    checksum = sha.digest()
    sha = hashlib.sha256()
    sha.update(checksum)
    checksum = sha.hexdigest()[0:8]
    address = (base58.b58encode(bytes(bytearray.fromhex(key_hash + checksum)))).decode('utf-8')

    return address