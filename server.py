import socket

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

public_private_keys = {}
public_rsa_encrypted_aes_keys = {}


def generate_public_private_rsa_keys():
    modulus_length = 2048
    key = RSA.generate(modulus_length)
    # print (key.exportKey())
    pub_key = key.publickey()
    # print (pub_key.exportKey())
    return key, pub_key


def decrypt_rsa(encoded_encrypted_msg, key):
    encryptor = PKCS1_OAEP.new(key)
    decoded_encrypted_msg = base64.b64decode(encoded_encrypted_msg)
    # print(decoded_encrypted_msg)
    decoded_decrypted_msg = encryptor.decrypt(decoded_encrypted_msg)
    # print(decoded_decrypted_msg)
    return decoded_decrypted_msg


def get_public_key():
    private, public = generate_public_private_rsa_keys()
    public_key_bytes = public.export_key('PEM')
    public_private_keys[public_key_bytes] = private
    return public_key_bytes


def get_public_key_request(server_socket, client_socket):
    response = get_public_key()
    client_socket.send(response)
    client_socket.close()


def post_encrypted_aes_request(server_socket, client_socket):
    client_socket.close()

    client_socket, addr = server_socket.accept()
    encrypted_aes_key = client_socket.recv(1024).decode('UTF-8')
    client_socket.close()

    client_socket, addr = server_socket.accept()
    public_key_bytes = client_socket.recv(1024)
    public_rsa_encrypted_aes_keys[public_key_bytes] = encrypted_aes_key
    client_socket.send(
        'Encrypted AES Key Saved Successfully In Server'.encode('UTF-8'))
    client_socket.close()


def get_decrypted_aes(server_socket, client_socket):
    client_socket.close()

    client_socket, addr = server_socket.accept()
    public_key_bytes = client_socket.recv(1024)
    private_key = public_private_keys[public_key_bytes]

    encrypted_aes_key = public_rsa_encrypted_aes_keys[public_key_bytes].encode(
        'UTF-8')
    decrypted_aes_key = decrypt_rsa(encrypted_aes_key, private_key)

    client_socket.send(decrypted_aes_key)
    client_socket.close()


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    SERVER_IP = 'localhost'
    SERVER_PORT = 5678

    server_socket.bind((SERVER_IP, SERVER_PORT))
    server_socket.listen(5)

    while True:
        client_socket, addr = server_socket.accept()

        request = client_socket.recv(1024).decode('UTF-8')
        print(request)

        response = 'No Response'.encode('UTF-8')
        if request == 'get_public_key':
            get_public_key_request(server_socket, client_socket)
        elif request == 'post_encrypted_aes':
            post_encrypted_aes_request(server_socket, client_socket)
        elif request == 'get_decrypted_aes':
            get_decrypted_aes(server_socket, client_socket)
        else:
            client_socket.send(response)
            client_socket.close()


if __name__ == "__main__":
    main()
