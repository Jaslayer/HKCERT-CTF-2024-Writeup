from Crypto.Cipher import AES
from Crypto.Util.number import *
from pwn import *
import json
import os

# interact with users

def receive(r):
    res = r.recvline().decode().strip()
    return json.loads(res)

def send(r, target, req):
    j = json.dumps(req, separators=(',', ':'))
    r.sendlineafter(f'🕊️'.encode(), f'{target} {j}'.encode())

# cryptographic toolbox

P = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff
G = 0x2

def derive_public_key(private_key: int):
    return pow(G, private_key, P)

def derive_session_key(other_public_key: int, self_private_key: int):
    shared_key = pow(other_public_key, self_private_key, P)
    session_key = hashlib.sha256(shared_key.to_bytes(512, 'big')).digest()
    return session_key
  
def encrypt(session_key: bytes, message: bytes) -> str:
    nonce = os.urandom(8)
    cipher = AES.new(session_key, AES.MODE_CTR, nonce=nonce)
    ciphertext = nonce + cipher.encrypt(message)
    return ciphertext.hex()

def decrypt(session_key: bytes, ciphertext: str) -> bytes:
    ciphertext = bytes.fromhex(ciphertext)
    nonce, ciphertext = ciphertext[:8], ciphertext[8:]
    cipher = AES.new(session_key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ciphertext)


# ===

def connect():
    return remote("c24b-pigeon-2.hkcert24.pwnable.hk", 1337, ssl=True)


def experiment2():
    FLAG = ""
    r = connect()

    j = receive(r)  # alice_public_key = j['public_key']
    j = receive(r)  # byron_public_key = j['public_key']
    j = receive(r)  # cipher_done = j['ciphertext']

    send(r, "byron", j)
    byron_secret = receive(r)
    
    send(r, 'alice', byron_secret)
    alice_secret = receive(r)
    print(f'{alice_secret["ciphertext"] = }')
    #print(f'{bytes.fromhex(alice_secret) = }')

    prefix, flag, postfix = (alice_secret["ciphertext"][:29*2],
                             alice_secret["ciphertext"][29*2:-1*2],
                             alice_secret["ciphertext"][-1*2:])
    
    flag_sz = len(flag) >> 1
    new_postfix = '00' if postfix == 'ff' else 'ff'

    for i in range(flag_sz) :
        for b in range(0x100) :
            guess = hex(int(flag[i*2:i*2+2], 16) ^ b)[2:].zfill(2)
            new_flag = flag[:i*2] + guess + flag[i*2+2:]
            # print(new_flag)
            new_payload = prefix + new_flag + new_postfix
            j['ciphertext'] = new_payload
            send(r, 'byron', j)
            byron_resp = receive(r)
            send(r, 'alice', byron_resp)
            alice_resp = receive(r)
            if len(alice_resp['ciphertext']) == 20: # :)
                FLAG += chr(b^ord('}'))
                print(FLAG)
                break



if __name__ == '__main__':
    experiment2()
