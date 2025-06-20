import base64
import os
import json
from Crypto.Cipher import DES3, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes

class MusicEncryption:
    def __init__(self):
        # Khởi tạo cặp khóa RSA 1024-bit
        self.key = RSA.generate(1024)
        self.public_key = self.key.publickey()
        
    def generate_session_key(self):
        # Tạo session key cho Triple DES (24 bytes)
        return get_random_bytes(24)
    
    def encrypt_session_key(self, session_key, public_key):
        # Mã hóa session key bằng RSA-OAEP
        cipher = PKCS1_OAEP.new(public_key)
        return cipher.encrypt(session_key)
    
    def decrypt_session_key(self, encrypted_session_key):
        # Giải mã session key bằng RSA-OAEP
        cipher = PKCS1_OAEP.new(self.key)
        return cipher.decrypt(encrypted_session_key)
    
    def sign_metadata(self, metadata):
        # Tạo chữ ký số cho metadata bằng RSA/SHA-512
        h = SHA512.new(json.dumps(metadata).encode())
        signature = pkcs1_15.new(self.key).sign(h)
        return signature
    
    def verify_signature(self, metadata, signature, public_key):
        # Xác thực chữ ký số
        try:
            h = SHA512.new(json.dumps(metadata).encode())
            pkcs1_15.new(public_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False
            
    def encrypt_file(self, file_path, session_key):
        # Đọc file và mã hóa bằng Triple DES
        iv = get_random_bytes(8)  # IV cho Triple DES
        cipher = DES3.new(session_key, DES3.MODE_CBC, iv)
        
        with open(file_path, 'rb') as f:
            data = f.read()
            # Padding
            pad_len = 8 - (len(data) % 8)
            data += bytes([pad_len]) * pad_len
            # Mã hóa
            ciphertext = cipher.encrypt(data)
            
        # Tính hash SHA-512
        h = SHA512.new()
        h.update(iv + ciphertext)
        file_hash = h.hexdigest()
        
        return {
            'iv': base64.b64encode(iv).decode('ascii').replace('\n', ''),
            'cipher': base64.b64encode(ciphertext).decode('ascii').replace('\n', ''),
            'hash': file_hash
        }
        
    def encrypt_metadata(self, metadata, des_key):
        # Mã hóa metadata bằng DES
        iv = get_random_bytes(8)
        cipher = DES.new(des_key, DES.MODE_CBC, iv)
        
        data = json.dumps(metadata).encode()
        # Padding
        pad_len = 8 - (len(data) % 8)
        data += bytes([pad_len]) * pad_len
        ciphertext = cipher.encrypt(data)
        
        return {
            'iv': base64.b64encode(iv).decode('ascii').replace('\n', ''),
            'cipher': base64.b64encode(ciphertext).decode('ascii').replace('\n', '')
        }
        
    def prepare_package(self, file_path, metadata, recipient_public_key):
        # Chuẩn bị gói tin để gửi
        session_key = self.generate_session_key()
        des_key = get_random_bytes(8)  # DES key cho metadata
        
        # Mã hóa file và metadata
        file_data = self.encrypt_file(file_path, session_key)
        meta_data = self.encrypt_metadata(metadata, des_key)
        
        # Ký metadata
        signature = self.sign_metadata(metadata)
        
        # Mã hóa session key và des key
        encrypted_session_key = self.encrypt_session_key(session_key, recipient_public_key)
        encrypted_des_key = self.encrypt_session_key(des_key, recipient_public_key)
        
        return {
            'iv': file_data['iv'],
            'cipher': file_data['cipher'],
            'meta': meta_data['cipher'],
            'meta_iv': meta_data['iv'],
            'hash': file_data['hash'],
            'sig': base64.b64encode(signature).decode('ascii').replace('\n', ''),
            'session_key': base64.b64encode(encrypted_session_key).decode('ascii').replace('\n', ''),
            'des_key': base64.b64encode(encrypted_des_key).decode('ascii').replace('\n', '')
        }
        
    def verify_and_decrypt(self, package, sender_public_key):
        try:
            # Giải mã các khóa
            encrypted_session_key = base64.b64decode(package['session_key'])
            encrypted_des_key = base64.b64decode(package['des_key'])
            session_key = self.decrypt_session_key(encrypted_session_key)
            des_key = self.decrypt_session_key(encrypted_des_key)
            
            # Giải mã metadata
            meta_iv = base64.b64decode(package['meta_iv'])
            meta_cipher = base64.b64decode(package['meta'])
            cipher = DES.new(des_key, DES.MODE_CBC, meta_iv)
            meta_data = cipher.decrypt(meta_cipher)
            # Xử lý padding
            pad_len = meta_data[-1]
            meta_data = meta_data[:-pad_len]
            metadata = json.loads(meta_data.decode())
            
            # Xác thực chữ ký
            signature = base64.b64decode(package['sig'])
            if not self.verify_signature(metadata, signature, sender_public_key):
                return False, "Chữ ký không hợp lệ"
                
            # Kiểm tra hash
            iv = base64.b64decode(package['iv'])
            ciphertext = base64.b64decode(package['cipher'])
            h = SHA512.new()
            h.update(iv + ciphertext)
            if h.hexdigest() != package['hash']:
                return False, "Hash không khớp"
                
            # Giải mã file
            cipher = DES3.new(session_key, DES3.MODE_CBC, iv)
            data = cipher.decrypt(ciphertext)
            # Xử lý padding
            pad_len = data[-1]
            data = data[:-pad_len]
            
            return True, {
                "data": data,
                "metadata": metadata
            }
            
        except Exception as e:
            return False, str(e)