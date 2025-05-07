from Crypto.Cipher import AES
import base64, os
import hashlib

def _pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]) * pad_len

def _unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def derive_key(secret_phrase: str) -> bytes:
    return hashlib.sha256(secret_phrase.encode()).digest()

def encrypt_msg(data: str, key: bytes) -> str:
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(_pad(data.encode()))
    return base64.b64encode(iv + encrypted).decode()

def decrypt_msg(data: str, key: bytes) -> str:
    raw = base64.b64decode(data.encode())
    iv, ct = raw[:16], raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return _unpad(cipher.decrypt(ct)).decode()
