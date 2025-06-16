from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib

def aes_encrypt(key: str, plaintext: str) -> str:
    key_bytes = hashlib.sha256(key.encode()).digest()
    cipher = AES.new(key_bytes, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + ct_bytes).decode()

def aes_decrypt(key: str, ciphertext: str) -> str:
    try:
        key_bytes = hashlib.sha256(key.encode()).digest()
        raw = base64.b64decode(ciphertext)
        iv = raw[:16]
        ct = raw[16:]
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode()
    except Exception:
        return ""
