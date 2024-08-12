import argparse
from getpass import getpass
from typing import List, Tuple
import json
from hashlib import scrypt, sha256
from base58 import b58decode_check, b58encode, b58encode_check
from Crypto.Cipher import AES  # pip install pycryptodome
from Crypto.PublicKey import ECC
from Crypto.Hash import RIPEMD160

def read_nep2_file(path: str) -> Tuple[List[Tuple[str, str]], Tuple[int, int, int]]:
    with open(path) as f:
        wallet = json.load(f)
    scrypt_args = wallet["scrypt"]
    (n, r, p) = scrypt_args["n"], scrypt_args["r"], scrypt_args["p"]
    accounts = [(account["address"], account["key"]) for account in wallet["accounts"]]
    return accounts, (n, r, p)

def nep2_to_private_key(nep2: str, passphrase: bytes, n=16384, r=8, p=8) -> bytes:
    nep2: bytes = b58decode_check(nep2)
    if len(nep2) != 39:
        raise ValueError(f'Invalid length {len(nep2)} for scrypted nep2 key')
    if nep2[0] != 0x01 or nep2[1] != 0x42 or nep2[2] != 0xe0:
        raise ValueError(f'Invalid nep2 that does not start with 0x0142e0')
    address_hash: bytes = nep2[3:7]
    derived_key: bytes = scrypt(passphrase, salt=address_hash, n=n, r=r, p=p, dklen=64)
    encrypted_key: bytes = nep2[7:39]  # len: 32
    private_key: bytes = xor_bytes(aes_ecb_decrypt(encrypted_key, derived_key[32:]), derived_key[:32])
    return private_key
    
def private_key_to_wif(private_key: bytes, compressed = True, version = b'\x80') -> str:
    data = version + private_key
    if compressed:
        data = data + b'\x01'
    checksum: bytes = sha256(sha256(data).digest()).digest()
    wif: str = b58encode(data + checksum[:4]).decode('utf-8')
    return wif

def aes_ecb_decrypt(ciphertext: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = cipher.decrypt(ciphertext)
    return decrypted_data

def xor_bytes(b1: bytes, b2: bytes) -> bytes:
    return b''.join([(b1 ^ b2).to_bytes(1, 'big') for b1, b2 in zip(b1, b2)])

def nep2wif(nep2: str, passphrase: str, compressed=True) -> Tuple[str, str]:
    private_key = nep2_to_private_key(nep2, passphrase.encode('utf-8'), n, r, p)
    wif = private_key_to_wif(private_key, compressed)
    return wif, address

def private_key_to_neo3_address(private_key: bytes) -> str:
    public_key = ECC.construct(curve='secp256r1', d=int.from_bytes(private_key, 'big')).pointQ
    x = public_key.x.to_bytes(32, 'big')
    prefix = b'\x02' if public_key.y % 2 == 0 else b'\x03'
    compressed_public_key = prefix + x
    verification_script = b'\x0c\x21' + compressed_public_key + b'\x41\x56\xe7\xb3\x27'
    ripemd160 = RIPEMD160.new()
    ripemd160.update(sha256(verification_script).digest())
    script_hash = ripemd160.digest()
    address = b58encode_check(b'\x35' + script_hash).decode('utf-8')
    return address

def t():  # test
    private_key = nep2_to_private_key("6PYM7jHL4GmS8Aw2iEFpuaHTCUKjhT4mwVqdoozGU6sUE25BjV4ePXDdLz", b"neo")
    assert private_key == bytes.fromhex("84180ac9d6eb6fba207ea4ef9d2200102d1ebeb4b9c07e2c6a738a42742e27a5")
    wif = private_key_to_wif(private_key, True)
    assert wif == "L1eV34wPoj9weqhGijdDLtVQzUpWGHszXXpdU9dPuh2nRFFzFa7E"
    address = private_key_to_neo3_address(private_key)
    assert address == "NM7Aky765FG8NhhwtxjXRx7jEL1cnw7PBP"

if __name__ == '__main__':
    t()
    parser = argparse.ArgumentParser(prog='nep2wif.py',
        description='Transform Neo3 json wallet in NEP-2 format to compressed WIF private key')
    parser.add_argument('path', help='Path to your json wallet file')
    path = parser.parse_args().path
    accounts, (n, r, p) = read_nep2_file(path)
    previous_passphrase = ''
    for i, (address, nep2) in enumerate(accounts):
        if i > 0:
            print('Input nothing and press Enter to use the previous passphrase.')
        input_passphrase = getpass(f"Input password for address {address}: ")
        if not input_passphrase:
            input_passphrase = previous_passphrase
        else:
            previous_passphrase = input_passphrase
        wif, addr = nep2wif(nep2, input_passphrase)
        if addr != address:
            print('Incorrect password. Skipping.')
            continue
        print(wif)
    input("Press Enter to exit.")