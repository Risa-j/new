#!/usr/bin/env python3
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import *
import binascii as ba
import socketserver
import sys
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import hashes


def encrypt_file(key, nonce, file_path, output_path):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), default_backend())
    encryptor = cipher.encryptor()
    with open(file_path, 'rb') as f:
        file_data = f.read()
    encrypted_data = encryptor.update(file_data) + encryptor.finalize()
    with open(output_path, 'wb') as f:
        f.write(encrypted_data)


def decrypt_file(key, nonce, file_path, output_path):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), default_backend())
    decryptor = cipher.decryptor()
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    with open(output_path, 'wb') as f:
        f.write(decrypted_data)


def encrypt_message(key, nonce, message):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message) + encryptor.finalize()
    return encrypted_message


def decrypt_message(key, nonce, encrypted_message):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
    return decrypted_message


def generate_hmac(key, message):
    hmac = HMAC(key, hashes.SHA256())
    hmac.update(message)
    return hmac.finalize()


def verify_hmac(key, message, received_hmac):
    hmac = HMAC(key, hashes.SHA256())
    hmac.update(message)
    try:
        hmac.verify(received_hmac)
        return True
    except InvalidSignature:
        return False


def load_dh_params():
    with open('./dh_2048_params.bin', 'rb') as f:
        params = load_der_parameters(f.read(), default_backend())
    print('Parameters have been read from file, Server is ready for requests ...')
    return params


def generate_dh_prvkey(params):
    return params.generate_private_key()


def check_client_pubkey(pubkey):
    if isinstance(pubkey, dh.DHPublicKey):
        return True
    else:
        return False


def get_PSK():
    with open('./PSK', 'rb') as f:
        PSK = f.readline().strip()
    return PSK


class Dh_Handler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server):
        self.params = load_dh_params()
        self.state = 0
        socketserver.BaseRequestHandler.__init__(self, request, client_address, server)

    def handle(self):
        self.data = self.request.recv(3072).strip()
        if self.state == 0 and self.data == get_PSK():
            self.state = 1
            print(self.data, self.state)
            response = b'Hey there!'
            self.request.sendall(response)
        else:
            response = b'Incorrect pre-shared key, hanging up'
            self.request.sendall(response)
            return

        self.data = self.request.recv(3072).strip()
        if self.state == 1 and self.data == b'Params?':
            self.state = 2
            print(self.data, self.state)
            dh_params = self.params
            response = dh_params.parameter_bytes(Encoding.PEM, ParameterFormat.PKCS3)
            self.request.sendall(response)
        else:
            response = b'I do not understand you, hanging up'
            self.request.sendall(response)
            return

        self.data = self.request.recv(3072).strip()
        if self.state == 2 and bytearray(self.data)[0:18] == b'Client public key:':
            client_pubkey = load_pem_public_key(bytes(bytearray(self.data)[18:]), default_backend())
            if client_pubkey:
                server_keypair = generate_dh_prvkey(self.params)
                response = b'Server public key:' + server_keypair.public_key().public_bytes(
                    Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
                shared_secret = server_keypair.exchange(client_pubkey)
                self.state = 3
                print(self.data, self.state)
                self.request.sendall(response)
                print('Shared Secret:\n{}'.format(ba.hexlify(shared_secret)))

            else:
                response = b'Invalid client public key, hanging up'
                self.request.sendall(response)
                return

        self.data = self.request.recv(3072).strip()
        if self.state == 3 and bytearray(self.data) == b'Please give me the nonce':
            kdf = HKDF(
                algorithm=hashes.SHA256(),
                length=48,
                salt=None,
                info=b'Handshake data',
                backend=default_backend()
            )

            key_material = kdf.derive(shared_secret)
            self.key = key_material[:16]
            self.mac_key = key_material[16:32]
            self.nonce = os.urandom(16)
            self.request.sendall(b'Server nonce:' + self.nonce)
            self.state = 4

        self.data = self.request.recv(3072).strip()
        if self.state == 4:
            response = b'Please choose the mode: 1: Talk 2: Transport File'
            self.request.sendall(response)
            self.state = 5

        self.data = self.request.recv(3072).strip()
        if self.state == 5 and bytearray(self.data) == b'1':
            response = b'Ok, We can start talk'
            self.request.sendall(response)
            self.state = 6
            print(response, self.state)

        elif self.state == 5 and bytearray(self.data) == b'2':
            response = b'Ok, You can transport file'
            self.request.sendall(response)
            self.state = 7
            print(response, self.state)

        else:
            response = b'Sorry, Your input is invalid, please reinput'
            self.request.sendall(response)
            self.state = 4

        if self.state == 6:
            while True:
                self.data = self.request.recv(3072).strip()
                received_message = self.data[:-32]
                received_hmac = self.data[-32:]
                print('Received: {}'.format(self.data))
                if verify_hmac(self.mac_key, received_message, received_hmac):
                    decrypted_message = decrypt_message(self.key, self.nonce, received_message)
                    print('After decrypted_message: {}'.format(decrypted_message.decode()))
                    response = input('Your response:')
                    if response == 'quit':
                        break
                    encrypted_response = encrypt_message(self.key, self.nonce, response.encode())
                    hmac = generate_hmac(self.mac_key, encrypted_response)
                    self.request.sendall(encrypted_response + hmac)
                    print("Send successfully")
                else:
                    print('Message authentication failed')
        elif self.state == 7:

            filedata = self.request.recv(3072).strip()
            received_file = filedata[:-32]
            received_hmac = filedata[-32:]

            if verify_hmac(self.mac_key, received_file, received_hmac):
                with open('received_file', 'wb') as f:
                    f.write(filedata)
                with open('decrypt_received_file', 'wb') as f:
                    f.write(decrypt_message(self.key, self.nonce, received_file))
                print('File received successfully.')
                self.request.sendall(b'File received.')
            else:
                print('File authentication failed')


def main():
    host, port = '', 7777
    dh_server = socketserver.TCPServer((host, port), Dh_Handler)
    try:
        dh_server.serve_forever()
    except KeyboardInterrupt:
        dh_server.shutdown()
        sys.exit(0)


if __name__ == '__main__':
    main()
