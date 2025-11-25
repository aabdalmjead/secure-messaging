import socket
import threading

HOST = "0.0.0.0"
PORT = 5000

clients = {}
public_keys = {}
message_history = []


def handle_client(conn, addr):
    print(f"New connection from {addr}")
    
    username = ""
    try:
        data = conn.recv(4096).decode().strip()
        print(f"Received: {data}")
        
        if "|" in data:
            parts = data.split("|")
            if len(parts) >= 2:
                username = parts[0]
                if len(parts) >= 3:
                    public_key = parts[2]
                    public_keys[username] = public_key
                    print(f"{username} registered with public key")
                else:
                    public_keys[username] = "no_key"
                    print(f"{username} registered (no key)")
                
                clients[username] = conn
                print(f"Online users: {list(clients.keys())}")
        
        
        while True:
            data = conn.recv(4096).decode().strip()
            if not data:
                break
                
            print(f"From {username}: {data}")
            
            
            if data.startswith("GETKEY|"):
                parts = data.split("|")
                if len(parts) >= 2:
                    target_user = parts[1]
                    print(f"{username} wants key for {target_user}")
                    
                    if target_user in public_keys and public_keys[target_user] != "no_key":
                        response = f"PUBLICKEY|{target_user}|{public_keys[target_user]}\n"
                        conn.sendall(response.encode())
                        print(f"Sent {target_user}'s key to {username}")
                    else:
                        print(f"Key not available for {target_user}")
            
            
            elif data.startswith("SESSIONKEY|"):
                parts = data.split("|")
                if len(parts) >= 3:
                    to_user = parts[1]
                    encrypted_key = parts[2]
                    
                    if to_user in clients:
                        forward_msg = f"SESSIONKEY_FROM|{username}|{encrypted_key}\n"
                        clients[to_user].sendall(forward_msg.encode())
                        print(f"Forwarded session key to {to_user}")
            
            
            elif data.startswith("MESSAGE|"):
                parts = data.split("|")
                if len(parts) >= 4:
                    to_user = parts[1]
                    encrypted_msg = parts[2]
                    signature = parts[3]
                    
                    if to_user in clients:
                        forward_msg = f"MESSAGE_FROM|{username}|{encrypted_msg}|{signature}\n"
                        clients[to_user].sendall(forward_msg.encode())
                        print(f"Forwarded message to {to_user}")
            
            
            elif data == "LISTUSERS":
                online_users = list(clients.keys())
                user_list = "Online: " + ", ".join(online_users) if online_users else "No other users online"
                conn.sendall(f"INFO|{user_list}\n".encode())
                print(f"Sent user list to {username}")
                        
    except Exception as e:
        print(f"Error with {username}: {e}")
    finally:
        if username:
            print(f"{username} disconnected")
            if username in clients:
                del clients[username]
            if username in public_keys:
                del public_keys[username]
        conn.close()


def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    
    print(f"Server started on {HOST}:{PORT}")
    print("Waiting for connections...")
    
    while True:
        conn, addr = server_socket.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.daemon = True
        thread.start()
        print(f"Active connections: {threading.active_count() - 1}")


if __name__ == "__main__":
    start_server()