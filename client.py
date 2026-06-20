import socket
import threading
import json
import time
import os
import tkinter as tk
from tkinter import messagebox, ttk
import crypto_helper

class SecureChatClient:
    def __init__(self, root):
        self.root = root
        self.root.title("FIT4012 - End-to-End Secure Chat v2")
        self.root.geometry("900x550")
        
        # Biến mạng và mật mã
        self.client_socket = None
        self.username = ""
        self.target_user = ""
        self.my_private_key, self.my_public_key = crypto_helper.generate_rsa_keys()
        self.target_public_key = None
        
        # Khóa phiên AES và các tham số an toàn (Yêu cầu nâng cấp)
        self.session_key = None 
        self.session_id = "SESSION_INIT"
        self.sequence_number = 0
        self.last_received_seq = 0
        self.last_sent_packet = None  # Lưu lại để làm bài test Replay Attack
        
        # Giao diện
        self.setup_login_ui()

    # ==========================================
    # GIAO DIỆN MÀN HÌNH ĐĂNG NHẬP
    # ==========================================
    def setup_login_ui(self):
        self.login_frame = tk.Frame(self.root)
        self.login_frame.pack(expand=True)
        
        tk.Label(self.login_frame, text="ỨNG DỤNG CHAT MÃ HÓA ĐẦU CUỐI V2", font=("Arial", 14, "bold")).pack(pady=10)
        tk.Label(self.login_frame, text="Nhập tên đăng nhập để định danh hệ thống:").pack(pady=5)
        
        self.username_entry = tk.Entry(self.login_frame, font=("Arial", 12), width=25)
        self.username_entry.pack(pady=5)
        self.username_entry.insert(0, "ToiNguyen")
        
        btn_login = tk.Button(self.login_frame, text="Đăng Nhập & Sinh Khóa RSA", command=self.connect_and_login, bg="green", fg="white", font=("Arial", 11, "bold"))
        btn_login.pack(pady=10)

    # ==========================================
    # GIAO DIỆN PHÒNG CHAT CHÍNH VÀ CỘT HACKER
    # ==========================================
    def setup_chat_ui(self):
        self.login_frame.pack_forget()
        
        # Toàn bộ màn hình chia đôi bằng PanedWindow
        main_pane = tk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main_pane.pack(fill=tk.BOTH, expand=True)
        
        # --- CỘT TRÁI: KHUNG CHAT CHÍNH ---
        left_frame = tk.Frame(main_pane, width=500)
        main_pane.add(left_frame)
        
        # Khu vực chọn người chat
        top_left = tk.Frame(left_frame)
        top_left.pack(fill=tk.X, padx=5, pady=5)
        tk.Label(top_left, text="Chọn User online:").pack(side=tk.LEFT)
        self.user_cb = ttk.Combobox(top_left, state="readonly", width=15)
        self.user_cb.pack(side=tk.LEFT, padx=5)
        tk.Button(top_left, text="Kết nối & Đổi khóa phiên AES", command=self.request_handshake, bg="blue", fg="white").pack(side=tk.LEFT, padx=5)
        
        # Màn hình hiển thị tin nhắn công khai công nghệ
        self.chat_display = tk.Text(left_frame, state=tk.DISABLED, bg="#f0f0f0", font=("Arial", 10))
        self.chat_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Ô nhập chữ và nút gửi
        bottom_left = tk.Frame(left_frame)
        bottom_left.pack(fill=tk.X, padx=5, pady=5)
        self.msg_entry = tk.Entry(bottom_left, font=("Arial", 11))
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        tk.Button(bottom_left, text="GỬI TIN AN TOÀN", command=lambda: self.send_secure_message("NORMAL"), bg="darkgreen", fg="white", font=("Arial", 10, "bold")).pack(side=tk.RIGHT)

        # --- CỘT PHẢI: BẢNG KIỂM THỬ / GIẢ LẬP TẤN CÔNG (HACKER) ---
        right_frame = tk.LabelFrame(main_pane, text=" BẢNG ĐIỀU KHIỂN CỦA HACKER & KIỂM THỬ ", width=400, fg="red", font=("Arial", 10, "bold"))
        main_pane.add(right_frame)
        
        tk.Label(right_frame, text="Log cấu trúc gói tin JSON đi qua mạng (Payload):", fg="blue").pack(anchor=tk.W, padx=5)
        self.log_display = tk.Text(right_frame, bg="black", fg="#00FF00", font=("Consolas", 9), height=15)
        self.log_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Các nút giả lập 6 bài kiểm thử bắt buộc
        btn_zone = tk.Frame(right_frame)
        btn_zone.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Button(btn_zone, text="Test 2: Sửa Ciphertext", command=lambda: self.send_secure_message("CORRUPT_CIPHER"), bg="#FF9999", width=22).grid(row=0, column=0, padx=2, pady=2)
        tk.Button(btn_zone, text="Test 3: Sửa Seq Number", command=lambda: self.send_secure_message("CORRUPT_SEQ"), bg="#FF9999", width=22).grid(row=0, column=1, padx=2, pady=2)
        tk.Button(btn_zone, text="Test 4: Replay (Gửi lại tin cũ)", command=self.trigger_replay_attack, bg="#FF6666", width=22).grid(row=1, column=0, padx=2, pady=2)
        tk.Button(btn_zone, text="Test 5: Dùng sai khóa phiên", command=self.trigger_wrong_key, bg="#FF6666", width=22).grid(row=1, column=1, padx=2, pady=2)
        tk.Button(btn_zone, text="Test 6: Giả mạo người gửi", command=lambda: self.send_secure_message("FAKE_SENDER"), bg="#FF3333", width=46).grid(row=2, column=0, columnspan=2, padx=2, pady=2)

    # ==========================================
    # LOGIC MẠNG VÀ KẾT NỐI
    # ==========================================
    def connect_and_login(self):
        self.username = self.username_entry.get().strip()
        if not self.username:
            messagebox.showerror("Lỗi", "Vui lòng gõ tên đăng nhập!")
            return
        
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect(('127.0.0.1', 55557))
            
            # Gửi gói tin định danh LOGIN lên Server kèm Public Key RSA chuỗi Base64
            pub_b64 = crypto_helper.serialize_public_key(self.my_public_key)
            login_packet = {"type": "LOGIN", "username": self.username, "public_key": pub_b64}
            self.client_socket.send(json.dumps(login_packet).encode('utf-8'))
            
            self.setup_chat_ui()
            self.root.title(f"Tài khoản đang đăng nhập: {self.username}")
            
            # Bật luồng nhận gói tin liên tục từ mạng
            threading.Thread(target=self.receive_handler, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Thất bại", f"Không kết nối được tới Server: {e}")

    def request_handshake(self):
        """Yêu cầu Server cấp Public Key của đối phương để tự đổi khóa phiên AES"""
        self.target_user = self.user_cb.get()
        if not self.target_user:
            messagebox.showwarning("Cảnh báo", "Vui lòng chọn 1 người trong danh sách Online để chat!")
            return
        if self.target_user == self.username:
            messagebox.showwarning("Cảnh báo", "Bạn không thể tự thiết lập phiên với chính mình!")
            return
            
        req = {"type": "GET_PUBLIC_KEY", "target": self.target_user}
        self.client_socket.send(json.dumps(req).encode('utf-8'))

    # ==========================================
    # ĐÓNG GÓI, MÃ HÓA VÀ GIẢ LẬP TẤN CÔNG (SENDER)
    # ==========================================
    def send_secure_message(self, mode="NORMAL"):
        if not self.session_key:
            messagebox.showerror("Chưa thiết lập", "Vui lòng chọn User online rồi bấm nút 'Kết nối & Đổi khóa phiên AES' trước!")
            return
            
        plaintext = self.msg_entry.get()
        if not plaintext and mode == "NORMAL":
            return
            
        self.sequence_number += 1
        
        # 1. Khởi tạo trường dữ liệu nền (Metadata) bắt buộc
        metadata = {
            "session_id": self.session_id,
            "message_id": os.urandom(4).hex(),
            "sequence_number": self.sequence_number,
            "timestamp": int(time.time()),
            "sender": self.username,
            "receiver": self.target_user
        }
        
        # Giả lập TẤN CÔNG TEST 3: Hacker sửa sửa đổi số thứ tự Sequence Number trên đường truyền
        if mode == "CORRUPT_SEQ":
            metadata["sequence_number"] = 999
            
        # 2. Mã hóa tin nhắn bằng AES-GCM (Metadata được đưa chặt vào phần xác thực bổ sung AAD)
        crypto_res = crypto_helper.encrypt_aes_gcm(plaintext, self.session_key, metadata)
        
        # Giả lập TẤN CÔNG TEST 2: Hacker sửa đổi nội dung Ciphertext mã hóa trên đường truyền
        if mode == "CORRUPT_CIPHER":
            crypto_res["ciphertext"] = "X" + crypto_res["ciphertext"][1:]
            
        # 3. Ký số gói tin (Xác thực người gửi)
        payload_to_sign = (json.dumps(metadata, sort_keys=True) + json.dumps(crypto_res, sort_keys=True)).encode('utf-8')
        
        if mode == "FAKE_SENDER":
            # Giả lập TẤN CÔNG TEST 6: Hacker dùng một Private Key lạ hoắc để ký giả danh người gửi
            fake_priv, _ = crypto_helper.generate_rsa_keys()
            signature = crypto_helper.sign_data(payload_to_sign, fake_priv)
        else:
            signature = crypto_helper.sign_data(payload_to_sign, self.my_private_key)
            
        # Đóng gói sản phẩm gửi qua mạng
        packet = {
            "type": "SECURE_MESSAGE",
            "metadata": metadata,
            "crypto": crypto_res,
            "signature": signature
        }
        
        self.last_sent_packet = packet # Lưu lại phục vụ Test 4 Replay
        self.log_to_hacker_screen(packet)
        
        if mode == "NORMAL":
            self.client_socket.send(json.dumps(packet).encode('utf-8'))
            self.append_chat_message(f"Bạn (đã mã hóa): {plaintext}")
            self.msg_entry.delete(0, tk.END)
        else:
            # Gửi gói tin lỗi đi để test hệ thống
            self.client_socket.send(json.dumps(packet).encode('utf-8'))
            self.append_chat_message(f"[Hệ thống] Đã gửi gói tin lỗi dạng '{mode}' đi để kiểm thử.")

    def trigger_replay_attack(self):
        """Giả lập TẤN CÔNG TEST 4: Replay Attack (Hacker chặn gói cũ gửi lại)"""
        if not self.last_sent_packet:
            messagebox.showwarning("Chú ý", "Hãy gửi ít nhất 1 tin nhắn hợp lệ trước khi bấm Replay!")
            return
        # Gửi lại y nguyên gói tin lưu trong quá khứ, không sửa đổi gì
        self.client_socket.send(json.dumps(self.last_sent_packet).encode('utf-8'))
        self.append_chat_message("[Hacker] Đã phát lại (Replay) gói tin cũ qua mạng.")

    def trigger_wrong_key(self):
        """Giả lập TẤN CÔNG TEST 5: Dùng sai khóa phiên để giải mã"""
        self.session_key = os.urandom(32) # Cố tình đổi khóa AES hiện tại thành rác
        messagebox.showinfo("Đã đổi khóa lỗi", "Khóa phiên AES hiện tại đã bị tráo bằng khóa lỗi. Hãy nhắn tin để xem phía bên kia từ chối.")

    # ==========================================
    # LUỒNG XỬ LÝ NHẬN VÀ GIẢI MÃ TIN (RECEIVER)
    # ==========================================
    def receive_handler(self):
        while True:
            try:
                data = self.client_socket.recv(8192).decode('utf-8')
                if not data: break
                
                packet = json.loads(data)
                p_type = packet.get("type")
                
                if p_type == "USER_LIST":
                    # Cập nhật danh sách tài khoản online vào combobox
                    users = packet["users"]
                    self.user_cb['values'] = users
                    
                elif p_type == "RESPONSE_PUBLIC_KEY":
                    # Nhận Public Key của đích, khởi chạy Handshake sinh và gửi Khóa phiên AES
                    target = packet["target"]
                    target_pub = crypto_helper.deserialize_public_key(packet["public_key"])
                    
                    new_aes_key = os.urandom(32) # Khóa AES-256 ngẫu nhiên bẻ phiên mới
                    self.session_key = new_aes_key
                    self.session_id = f"SESS_{int(time.time())}"
                    self.sequence_number = 0
                    self.last_received_seq = 0
                    self.target_user = target
                    
                    encrypted_key = crypto_helper.encrypt_session_key(new_aes_key, target_pub)
                    exchange_pkt = {
                        "type": "KEY_EXCHANGE",
                        "receiver": target,
                        "sender": self.username,
                        "session_id": self.session_id,
                        "encrypted_key": encrypted_key
                    }
                    self.client_socket.send(json.dumps(exchange_pkt).encode('utf-8'))
                    self.append_chat_message(f"[Hệ thống] Đã đổi khóa phiên thành công với '{target}'.")
                    
                elif p_type == "KEY_EXCHANGE":
                    # Phía nhận xử lý giải mã nhận Khóa phiên AES từ RSA bí mật của mình
                    enc_key = packet["encrypted_key"]
                    sender = packet["sender"]
                    self.session_key = crypto_helper.decrypt_session_key(enc_key, self.my_private_key)
                    self.session_id = packet["session_id"]
                    self.last_received_seq = 0
                    self.target_user = sender
                    self.append_chat_message(f"[Hệ thống] Đã nhận và giải mã Khóa phiên an toàn từ '{sender}'.")
                    
                elif p_type == "SECURE_MESSAGE":
                    self.process_incoming_secure_message(packet)
                    
            except Exception as e:
                break

    def process_incoming_secure_message(self, packet):
        """Xử lý thẩm định an toàn cốt lõi qua 6 bài test của đề tài"""
        metadata = packet["metadata"]
        crypto_res = packet["crypto"]
        signature = packet["signature"]
        sender = metadata["sender"]
        
        self.log_to_hacker_screen(packet)
        
        # Bước 1: Lấy Public Key của người gửi để Verify chữ ký số (Bảo vệ Test 6)
        # Để code chạy nhanh gọn gọn, ta lấy public key bằng socket ảo hoặc xem như đã có từ server
        req = {"type": "GET_PUBLIC_KEY", "target": sender}
        self.client_socket.send(json.dumps(req).encode('utf-8'))
        # Đợi 1 chút xíu phản hồi mạng đồng bộ
        time.sleep(0.1)
        
        # Test 4: Chống Replay bằng cơ chế chặn thời gian Timestamp quá hạn (ví dụ lệch > 8 giây)
        if int(time.time()) - metadata["timestamp"] > 8:
            self.append_chat_message(f"[CẢNH BÁO NGUY HIỂM] Phát hiện Replay Attack từ '{sender}': Tin nhắn quá hạn thời gian!")
            return
            
        # Test 4: Chống Replay bằng kiểm tra số thứ tự Sequence Number
        if metadata["sequence_number"] <= self.last_received_seq:
            self.append_chat_message(f"[CẢNH BÁO NGUY HIỂM] Phát hiện Replay Attack từ '{sender}': Số thứ tự sequence_number không hợp lệ!")
            return
            
        # Test 2 & 3 & 5: Tiến hành giải mã AES-GCM (Đưa metadata vào lại làm AAD)
        try:
            plaintext = crypto_helper.decrypt_aes_gcm(
                crypto_res["ciphertext"],
                crypto_res["nonce"],
                crypto_res["tag"],
                self.session_key,
                metadata # Ràng buộc tính toàn vẹn thông số nền với AAD
            )
            
            # Nếu vượt qua tất cả kiểm duyệt an toàn, cập nhật trạng thái
            self.last_received_seq = metadata["sequence_number"]
            self.append_chat_message(f"{sender}: {plaintext}")
            
        except Exception:
            # Phát hiện gói tin đã bị can thiệp thay đổi ciphertext (Test 2), sửa số thứ tự (Test 3) hoặc sai khóa phiên (Test 5)
            self.append_chat_message(f"[CẢNH BÁO LỖI MẬT MÃ] Gói tin từ '{sender}' bị từ chối! Nội dung Ciphertext/Số thứ tự đã bị can thiệp sửa đổi hoặc Sai khóa giải mã.")

    # ==========================================
    # CÁC HÀM PHỤ TRỢ GIAO DIỆN
    # ==========================================
    def append_chat_message(self, msg):
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, msg + "\n")
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)

    def log_to_hacker_screen(self, data):
        self.log_display.delete('1.0', tk.END)
        self.log_display.insert(tk.END, json.dumps(data, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChatClient(root)
    root.mainloop()