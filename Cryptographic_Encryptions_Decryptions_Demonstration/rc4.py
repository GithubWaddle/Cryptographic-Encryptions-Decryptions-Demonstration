from Crypto.Cipher import ARC4
import hashlib
import base64

def rc4_encrypt(key: str, plaintext: str) -> str:
    key_bytes = hashlib.sha256(key.encode()).digest()
    cipher = ARC4.new(key_bytes)
    ct = cipher.encrypt(plaintext.encode())
    return base64.b64encode(ct).decode()

def rc4_decrypt(key: str, ciphertext: str) -> str:
    try:
        key_bytes = hashlib.sha256(key.encode()).digest()
        cipher = ARC4.new(key_bytes)
        ct = base64.b64decode(ciphertext)
        pt = cipher.decrypt(ct)
        return pt.decode()
    except Exception:
        return ""
