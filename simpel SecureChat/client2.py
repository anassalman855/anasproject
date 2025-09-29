import socket
from tkinter import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
import threading

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

def start_client():

    host = '127.0.0.1'
    port = 8082
    encryption_key = b'Sixteen byte key'



    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    print("تم الاتصال بالخادم.")

    def send_message():


        message = message_entry.get()

        if message:
            encrypted_message = encrypt_message(message, encryption_key)

            client_socket.send(encrypted_message)


            message_box.config(state=NORMAL)
            message_box.insert(END, f"أنا: {message}\n")
            message_box.config(state=DISABLED)
            message_entry.delete(0, END)


    def receive_messages():



        while True:
            try:
                encrypted_message = client_socket.recv(1024)

                if encrypted_message:
                    message = decrypt_message(encrypted_message, encryption_key)


                    message_box.config(state=NORMAL)
                    message_box.insert(END, f"الآخر: {message}\n")
                    message_box.config(state=DISABLED)
            except Exception as e:
                print(f"خطأ أثناء استقبال الرسالة: {e}")
                break


    root = Tk()
    root.title("واجهة العميل")



    message_box = Text(root, height=15, width=50, state=DISABLED)
    message_box.pack(pady=10)

    # حقل لإدخال الرسائل
    message_entry = Entry(root, width=40)
    message_entry.pack(side=LEFT, padx=5)


    send_button = Button(root, text="إرسال", command=send_message)
    send_button.pack(side=LEFT)


    threading.Thread(target=receive_messages, daemon=True).start()

    root.mainloop()  #

    client_socket.close()


if __name__ == "__main__":
    start_client()
