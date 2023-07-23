#!/usr/bin/env python3
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import *
import binascii as ba
import socketserver
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import hashes


def get_PSK():
    with open('./PSK','rb') as f:
        PSK = f.readline().strip()
    return PSK
    
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

def encrypt_message(key,nonce,message):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message) + encryptor.finalize()
    return encrypted_message

def decrypt_message(key,nonce,encrypted_message):
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


def main():
    host, port = 'localhost', 7777
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    request = get_PSK(); 
    sock.sendall(request)
    received = sock.recv(3072).strip()
    print('Received:\n{}'.format(received))
    if received == b'Hey there!':
        request = b'Params?'
        sock.sendall(request)
    else:
        print('Pre-shared key is incorrect.')
        sock.close()
        return

    received = sock.recv(3072).strip()
    print('Received:\n{}'.format(received))
    dh_params = load_pem_parameters(received, default_backend())
    if isinstance(dh_params, dh.DHParameters):
        client_keypair = dh_params.generate_private_key()
        request = b'Client public key:' + client_keypair.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        sock.sendall(request)
    else:
        print('Bad response')
        sock.close()
        return

    received = sock.recv(3072).strip()
    print('Received:\n{}'.format(received))
    if bytearray(received)[0:18] == b'Server public key:':
        server_pubkey = load_pem_public_key(bytes(bytearray(received)[18:]), default_backend())
        if isinstance(server_pubkey, dh.DHPublicKey):
            shared_secret = client_keypair.exchange(server_pubkey)
            print('Shared Secret\n{}'.format(ba.hexlify(shared_secret)))
            kdf = HKDF(  
                algorithm=hashes.SHA256(),
                length=48,
                salt=None,
                info=b'Handshake data',
                backend=default_backend()
            )
            key_material = kdf.derive(shared_secret)
            key = key_material[:16]
            mac_key = key_material[16:32]
            request = b'Please give me the nonce'
            sock.sendall(request)

    received = sock.recv(3072).strip()
    print('Received:\n{}'.format(received))
    nonce_start = received.find(b'Server nonce:') + len('Server nonce:')
    nonce = received[nonce_start:].strip()
    request = b'I have get the nonce'
    sock.sendall(request)

    
    received = sock.recv(3072).strip() 
    print('Received:\n{}'.format(received))
    request = input("Mode:")
    sock.sendall(request.encode()) 
    
    received = sock.recv(3072).strip() 
    print('Received:\n{}'.format(received))
    if bytearray(received) == b'Ok, We can start talk':
        while True:
            message = input('Your message: ')
            if message == 'quit':
                break
            encrypted_message = encrypt_message(key,nonce,message.encode())
            hmac = generate_hmac(mac_key, encrypted_message)
            sock.sendall(encrypted_message + hmac)
            print("Send successfully")
            response = sock.recv(3072).strip()
            received_message = response[:-32]
            received_hmac = response[-32:]
            print('Received: {}'.format(response))
            if verify_hmac(mac_key, received_message, received_hmac):
                decrypted_message = decrypt_message(key,nonce,received_message)
                print('After decrypted message:\n{}'.format(decrypted_message.decode()))
            else:
                print('Message authentication failed') 

    elif bytearray(received) == b'Ok, You can transport file':
        while True:
            filename = input("Enter the filename: ")
            with open(filename, 'rb') as f:
                filedata = f.read()
            
            encrypted_file = encrypt_message(key,nonce,filedata)
            hmac = generate_hmac(mac_key, encrypted_file)
            
            sock.sendall(encrypted_file + hmac)
            received = sock.recv(3072).strip() 
            print('Received:\n{}'.format(received))
        
            

if __name__ == '__main__':
    main()
