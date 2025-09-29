import socket
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

def encrypt_message(message, encryption_key):

    cipher = Cipher(algorithms.AES(encryption_key), modes.ECB())
    encryptor = cipher.encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode('utf-8')) + padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize()

def decrypt_message(encrypted_message, encryption_key):

    cipher = Cipher(algorithms.AES(encryption_key), modes.ECB())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_message) + decryptor.finalize()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    return (unpadder.update(decrypted_padded_data) + unpadder.finalize()).decode('utf-8')

def handle_client(client_socket, other_client_socket, encryption_key, client_id):

    print(f"بدأ الاتصال مع العميل {client_id}")
    while True:
        try:
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message:
                print(f"العميل {client_id} أغلق الاتصال.")
                break

            message = decrypt_message(encrypted_message, encryption_key)
            print(f"العميل {client_id} قال: {message}")

            if other_client_socket:
                encrypted_message_to_send = encrypt_message(message, encryption_key)
                other_client_socket.send(encrypted_message_to_send)
        except Exception as e:
            print(f"خطأ مع العميل {client_id}: {e}")
            break

    client_socket.close()

def start_server():

    host = '127.0.0.1'
    port = 8082
    encryption_key = b'Sixteen byte key'

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(2)
    print("الخادم يعمل وينتظر اتصال العملاء...")

    client1_socket, client1_addr = server_socket.accept()
    print(f"اتصال وارد من العميل الأول: {client1_addr}")

    client2_socket, client2_addr = server_socket.accept()
    print(f"اتصال وارد من العميل الثاني: {client2_addr}")

    thread1 = threading.Thread(target=handle_client, args=(client1_socket, client2_socket, encryption_key, "Client 1"))
    thread2 = threading.Thread(target=handle_client, args=(client2_socket, client1_socket, encryption_key, "Client 2"))

    thread1.start()
    thread2.start()

    thread1.join()
    thread2.join()

    server_socket.close()
    print("تم إغلاق الخادم.")
if __name__ == "__main__":
    start_server()
