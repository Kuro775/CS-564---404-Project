asdsadsad# Operation Blacktrail: Covert Implant and C2 System

## Overview

Operation Blacktrail is a full-spectrum cyber effect designed to establish persistent control over a compromised Linux machine. The project leverages initial web-based exploitation and privilege escalation to deploy a covert implant that communicates with an encrypted C2 server. The system uses multiple stealth techniques, including AES-256 encryption, HTTP traffic mimicry, and optional steganographic data exfiltration.

### Features

* Remote shell command execution
* Encrypted file upload and download
* HTTP-mimicking C2 communication (AES-256 CBC)
* Steganographic data exfiltration via LSB-encoded PNG images
* Automatic persistence via .bashrc and cron jobs
* Self-cleanup and anti-forensic routines

## System Requirements

* Python 3.8+
* Libraries: pycryptodome, Pillow
* OS: Linux (Ubuntu 22.04 recommended for testing)

### Installation

```bash
pip install pycryptodome pillow
```

## C2 Server Usage

Start the C2 server on the attacker machine:

```bash
python3 c2_server.py
```

### Command Examples

* Run shell command:

  ```
  C2> whoami
  ```
* Download a file:

  ```
  C2> download:/etc/passwd
  ```
* Upload a file:

  ```
  C2> upload:/tmp/payload.sh
  ```
* Cleanup the implant:

  ```
  C2> cleanup
  ```

## Implant Usage

Deploy and start the implant on the target machine:

```bash
python3 implant.py
```

### Steganographic Exfiltration

By default, short outputs (like `whoami`) are transmitted as encrypted text. For longer outputs, the implant uses image-based exfiltration. This can be toggled using the `STEGO` prefix.

#### Example:

```bash
C2> id
# [Stego Output]: uid=1000(user) gid=1000(user) groups=...
```

## Troubleshooting

* **Data must be padded to 16 byte boundary**: Check that you are not double-encoding data before sending.
* **Connection refused**: Ensure that the C2 server is running and the firewall allows port 4433.

## Security Considerations

* All communication is encrypted to evade network detection.
* Traffic appears as regular HTTP POST requests.
* Self-destruct commands remove traces from disk and memory.

## Acknowledgements

This project was developed as part of the CS564 Cyber Effects course at UMass Amherst.
