import socket
import threading
import os
import base64
import time

from crypto_utils import encrypt_with_aes_key, decrypt_with_aes_key
from rsa_utils import generate_rsa_key_pair, encrypt_with_public_key, decrypt_with_private_key, sign_message, verify_signature

SERVER_IP = "127.0.0.1"
SERVER_PORT = 5000

session_keys = {}
public_keys = {}

def load_or_create_keys(username):
    priv_file = f"private_{username}.pem"
    pub_file = f"public_{username}.pem"

    if os.path.exists(priv_file) and os.path.exists(pub_file):
        print(f"Loading existing keys for {username}")
        with open(priv_file, "rb") as f:
            private_key = f.read()
        with open(pub_file, "rb") as f:
            public_key = f.read()
        return private_key, public_key

    print(f"Generating new keys for {username}")
    private_key, public_key = generate_rsa_key_pair()
    
    with open(priv_file, "wb") as f:
        f.write(private_key)
    with open(pub_file, "wb") as f:
        f.write(public_key)
    
    return private_key, public_key

def listener(sock, private_key):
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                print("Disconnected from server.")
                break

            text = data.decode().strip()
            print(f"Received: {text}")

            
            if text.startswith("PUBLICKEY|"):
                parts = text.split("|")
                if len(parts) >= 3:
                    user = parts[1]
                    b64_key = parts[2]
                    public_keys[user] = base64.b64decode(b64_key.encode())
                    print(f"Got public key for {user}")
                continue

            
            if text.startswith("SESSIONKEY_FROM|"):
                parts = text.split("|")
                if len(parts) >= 3:
                    from_user = parts[1]
                    encrypted_key = parts[2]
                    aes_key = decrypt_with_private_key(private_key, encrypted_key)
                    session_keys[from_user] = aes_key
                    print(f"Got AES key from {from_user}")
                    
                    
                    sock.sendall(f"GETKEY|{from_user}\n".encode())
                    print(f"Requested public key for {from_user} for verification")
                continue

            
            if text.startswith("MESSAGE_FROM|"):
                parts = text.split("|")
                if len(parts) >= 4:
                    from_user = parts[1]
                    encrypted_msg = parts[2]
                    signature_b64 = parts[3]

                    if from_user in session_keys:
                        aes_key = session_keys[from_user]
                        plaintext = decrypt_with_aes_key(encrypted_msg, aes_key)
                        
                        
                        if from_user in public_keys:
                            sender_pub = public_keys[from_user]
                            ok = verify_signature(sender_pub, plaintext.encode(), signature_b64)
                            if ok:
                                status = "VERIFIED"
                            else:
                                status = "INVALID SIGNATURE"
                        else:
                            status = "UNVERIFIED (no public key)"
                            
                        print(f"\n{status} {from_user}: {plaintext}")
                        print("To> ", end="", flush=True)

        except Exception as e:
            print(f"Error in listener: {e}")
            break

def main():
    username = input("Enter username: ").strip()
    private_key, public_key = load_or_create_keys(username)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_IP, SERVER_PORT))
        print(f"Connected to server")
    except:
        print("Cannot connect to server!")
        return

    
    b64_pub = base64.b64encode(public_key).decode()
    sock.sendall(f"{username}|PUBKEY|{b64_pub}\n".encode())
    print("Sent username and public key to server")

    
    thread = threading.Thread(target=listener, args=(sock, private_key), daemon=True)
    thread.start()

    print("\n[READY] You can start chatting")
    print("Commands: /quit to exit, /users to see online users")
    print()

    while True:
        try:
            to_user = input("To> ").strip()
            if not to_user:
                continue

            if to_user.lower() == "/quit":
                break
                
            if to_user.lower() == "/users":
                sock.sendall("LISTUSERS\n".encode())
                continue

            msg = input("Message> ").strip()
            if not msg:
                continue

            
            if to_user not in session_keys:
                print(f"Setting up secure session with {to_user}...")
                
                
                sock.sendall(f"GETKEY|{to_user}\n".encode())
                print(f"Requested public key for {to_user}")
                
                
                waited = 0
                while to_user not in public_keys:
                    time.sleep(0.5)
                    waited += 0.5
                    if waited > 10:
                        print(f"Timeout: {to_user} not responding")
                        break
                
                if to_user not in public_keys:
                    continue

                
                aes_key = os.urandom(16)
                session_keys[to_user] = aes_key
                encrypted_aes = encrypt_with_public_key(public_keys[to_user], aes_key)
                sock.sendall(f"SESSIONKEY|{to_user}|{encrypted_aes}\n".encode())
                print("Session key sent!")

            
            aes_key = session_keys[to_user]
            encrypted_msg = encrypt_with_aes_key(msg, aes_key)
            signature_b64 = sign_message(private_key, msg.encode())
            
            sock.sendall(f"MESSAGE|{to_user}|{encrypted_msg}|{signature_b64}\n".encode())
            print(f"Message sent to {to_user}")

        except KeyboardInterrupt:
            print("\nGoodbye!")
            break
        except Exception as e:
            print(f"Error: {e}")

    sock.close()
    print("Client closed.")


if __name__ == "__main__":
    main()