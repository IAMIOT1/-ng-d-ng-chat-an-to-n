import json
import base64
import time
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# ==========================================
# 1. QUẢN LÝ KHÓA RSA (BẤT ĐỐI XỨNG)
# ==========================================

def generate_rsa_keys():
    """Sinh cặp khóa RSA 2048 bit cho người dùng"""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    """Chuyển đổi Public Key thành chuỗi Base64 để gửi lên Server"""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo  # Đã sửa thành PublicFormat
    )
    return base64.b64encode(pem).decode('utf-8')

def deserialize_public_key(pub_key_b64):
    """Chuyển chuỗi Base64 ngược lại thành đối tượng Public Key"""
    pem = base64.b64decode(pub_key_b64.encode('utf-8'))
    return serialization.load_pem_public_key(pem)

# ==========================================
# 2. TRAO ĐỔI KHÓA PHIÊN (RSA-OAEP)
# ==========================================

def encrypt_session_key(session_key, target_public_key):
    """Dùng Public Key của người nhận để mã hóa Khóa phiên AES"""
    encrypted = target_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_session_key(encrypted_key_b64, my_private_key):
    """Dùng Private Key của mình để giải mã lấy Khóa phiên AES"""
    encrypted_key = base64.b64decode(encrypted_key_b64.encode('utf-8'))
    return my_private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# ==========================================
# 3. MÁ HÓA TIN NHẮN ĐẦU CUỐI (AES-GCM + AAD)
# ==========================================

def encrypt_aes_gcm(plaintext, session_key, metadata):
    """
    Mã hóa tin nhắn bằng AES-GCM.
    Đưa metadata (sequence_number, timestamp...) vào AAD để chống sửa đổi.
    """
    nonce = os.urandom(12)  # Nonce ngẫu nhiên 12 bytes bắt buộc cho GCM
    aad = json.dumps(metadata, sort_keys=True).encode('utf-8')
    
    encryptor = Cipher(
        algorithms.AES(session_key),
        modes.GCM(nonce),
    ).encryptor()
    
    encryptor.authenticate_additional_data(aad) # Khóa chặt dữ liệu nền vào gói tin
    ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
    
    return {
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "tag": base64.b64encode(encryptor.tag).decode('utf-8')
    }

def decrypt_aes_gcm(ciphertext_b64, nonce_b64, tag_b64, session_key, metadata):
    """Giải mã AES-GCM và xác thực tính toàn vẹn của dữ liệu qua AAD"""
    ciphertext = base64.b64decode(ciphertext_b64.encode('utf-8'))
    nonce = base64.b64decode(nonce_b64.encode('utf-8'))
    tag = base64.b64decode(tag_b64.encode('utf-8'))
    aad = json.dumps(metadata, sort_keys=True).encode('utf-8')
    
    decryptor = Cipher(
        algorithms.AES(session_key),
        modes.GCM(nonce, tag),
    ).decryptor()
    
    decryptor.authenticate_additional_data(aad)
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode('utf-8')

# ==========================================
# 4. XÁC THỰC NGƯỜI GỬI (CHỮ KÝ SỐ RSA-PSS)
# ==========================================

def sign_data(data_bytes, private_key):
    """Dùng Private Key của người gửi để tạo chữ ký số"""
    signature = private_key.sign(
        data_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(data_bytes, signature_b64, public_key):
    """Dùng Public Key của người gửi để kiểm tra chữ ký số"""
    signature = base64.b64decode(signature_b64.encode('utf-8'))
    try:
        public_key.verify(
            signature,
            data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False