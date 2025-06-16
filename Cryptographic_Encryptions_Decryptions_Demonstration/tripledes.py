from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import hashlib
import base64

def _create_3des_key(key: str) -> bytes:
    hashed_key = hashlib.md5(key.encode()).digest()
    return DES3.adjust_key_parity(hashed_key + hashed_key[:8])

def tripledes_encrypt(key: str, plaintext: str) -> str:
    key_bytes = _create_3des_key(key)
    cipher = DES3.new(key_bytes, DES3.MODE_CBC)
    ct = cipher.encrypt(pad(plaintext.encode(), DES3.block_size))
    return base64.b64encode(cipher.iv + ct).decode()

def tripledes_decrypt(key: str, ciphertext: str) -> str:
    try:
        key_bytes = _create_3des_key(key)
        raw = base64.b64decode(ciphertext)
        iv = raw[:8]
        ct = raw[8:]
        cipher = DES3.new(key_bytes, DES3.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), DES3.block_size)
        return pt.decode()
    except Exception:
        return ""
