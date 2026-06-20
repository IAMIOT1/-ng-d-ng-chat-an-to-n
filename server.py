import socket
import threading
import json

HOST = '127.0.0.1'
PORT = 55557

# Bộ nhớ lưu trữ: { "username": { "socket": conn, "public_key": "chuỗi_b64" } }
ONLINE_USERS = {}

def handle_client(conn, addr):
    username = None
    try:
        while True:
            data = conn.recv(8192).decode('utf-8')
            if not data:
                break
            
            packet = json.loads(data)
            msg_type = packet.get("type")
            
            # 1. ĐĂNG NHẬP / ĐỊNH DANH USER KHỞI TẠO
            if msg_type == "LOGIN":
                username = packet["username"]
                ONLINE_USERS[username] = {
                    "socket": conn,
                    "public_key": packet["public_key"]
                }
                print(f"[+] Người dùng '{username}' đăng nhập thành công.")
                broadcast_user_list()
                
            # 2. TRẢ PUBLIC KEY ĐỂ CLIENT TỰ HANDSHAKE ĐỔI KHÓA AES
            elif msg_type == "GET_PUBLIC_KEY":
                target = packet["target"]
                if target in ONLINE_USERS:
                    response = {
                        "type": "RESPONSE_PUBLIC_KEY",
                        "target": target,
                        "public_key": ONLINE_USERS[target]["public_key"]
                    }
                    conn.send(json.dumps(response).encode('utf-8'))
            
            # 3. CHUYỂN TIẾP GÓI TIN CHAT/KEY EXCHANGE ĐÃ MÃ HÓA
            elif msg_type in ["SECURE_MESSAGE", "KEY_EXCHANGE"]:
                receiver = packet.get("receiver") or packet.get("metadata", {}).get("receiver")
                if receiver in ONLINE_USERS:
                    ONLINE_USERS[receiver]["socket"].send(json.dumps(packet).encode('utf-8'))
                    
    except Exception as e:
        print(f"[-] Kết nối với '{username}' bị gián đoạn: {e}")
    finally:
        if username in ONLINE_USERS:
            del ONLINE_USERS[username]
            print(f"[-] Người dùng '{username}' đã thoát.")
            broadcast_user_list()
        conn.close()

def broadcast_user_list():
    """Gửi danh sách cập nhật các user đang online cho mọi người chọn"""
    user_list = list(ONLINE_USERS.keys())
    packet = {"type": "USER_LIST", "users": user_list}
    for user in ONLINE_USERS.values():
        try:
            user["socket"].send(json.dumps(packet).encode('utf-8'))
        except:
            pass

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[*] SERVER BẢO MẬT FIT4012 đang chạy ổn định tại {HOST}:{PORT}...")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    start_server()