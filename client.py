import socket
import json
import zlib
import base64
from Crypto.PublicKey import RSA
from music_encryption import MusicEncryption

def send_file(file_path, metadata, server_host='192.168.1.xxx', server_port=8000):  # Thay xxx bằng IP thực của server
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Đặt timeout 10 giây cho kết nối
    client.settimeout(10)
    try:
        print(f"Đang thử kết nối đến server {server_host}:{server_port}...")
        # Kết nối đến server
        client.connect((server_host, server_port))
        print(f"Đã kết nối tới server tại {server_host}:{server_port}")
        
        # Handshake
        client.send("Hello!".encode())
        response = client.recv(1024).decode()
        
        if response != "Ready!":
            print("Lỗi handshake")
            client.close()
            return
            
        print("Handshake thành công!")
        
        # Chuẩn bị và gửi package
        try:
            # Khởi tạo đối tượng mã hóa với khóa riêng của client
            client_encryption = MusicEncryption()
            
            # Lưu client public key để server có thể xác thực
            with open("client_public.pem", "wb") as f:
                f.write(client_encryption.public_key.export_key('PEM'))
            
            print("Đọc khóa công khai của server...")
            with open("server_public.pem", "rb") as f:
                server_public_key = RSA.import_key(f.read())
            
            print("Đang mã hóa file và metadata...")
            package = client_encryption.prepare_package(file_path, metadata, server_public_key)
            
            print("Đang gửi dữ liệu đã mã hóa...")
            # Gửi package đã nén
            package_json = json.dumps(package)
            compressed_data = zlib.compress(package_json.encode())
            
            # Gửi kích thước dữ liệu nén
            client.send(str(len(compressed_data)).encode())
            client.recv(1024)  # Chờ ACK
            
            # Gửi dữ liệu nén theo từng phần
            chunk_size = 4096
            for i in range(0, len(compressed_data), chunk_size):
                chunk = compressed_data[i:i + chunk_size]
                client.send(chunk)
            
            client.recv(1024)  # Chờ ACK
            
            # Nhận phản hồi
            response = client.recv(1024).decode()
            if response == "ACK":
                print("File đã được gửi và xác thực thành công!")
            else:
                print("Lỗi khi gửi file:", response)
                
        except Exception as e:
            print(f"Lỗi: {str(e)}")
        
    except ConnectionRefusedError:
        print(f"Không thể kết nối đến server tại {server_host}:{server_port}")
    except Exception as e:
        print(f"Lỗi: {str(e)}")
    finally:
        client.close()

if __name__ == "__main__":
    # Metadata của file nhạc
    metadata = {
        "title": "Example Song",
        "artist": "Example Artist",
        "copyright": "© 2024 Example Copyright",
        "license": "All rights reserved"
    }
    
    # Gửi file với metadata
    print("Bắt đầu gửi file...")
    send_file("song.mp3", metadata)