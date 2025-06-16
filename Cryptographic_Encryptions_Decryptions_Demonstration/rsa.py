from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

def rsa_generate_keys():
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key

def rsa_encrypt(public_key, plaintext: str) -> str:
    cipher = PKCS1_OAEP.new(public_key)
    ct = cipher.encrypt(plaintext.encode())
    return base64.b64encode(ct).decode()

def rsa_decrypt(private_key, ciphertext: str) -> str:
    try:
        cipher = PKCS1_OAEP.new(private_key)
        ct = base64.b64decode(ciphertext)
        pt = cipher.decrypt(ct)
        return pt.decode()
    except Exception:
        return ""
