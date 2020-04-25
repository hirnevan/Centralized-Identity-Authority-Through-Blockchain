from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, hmac, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def decrypt(encrypt_key, encrypted):
    cipher = Cipher(algorithms.AES(encrypt_key),
                    modes.ECB(),
                    backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    unpadded = unpadder.update(decrypted)
    unpadded += unpadder.finalize()
    return unpadded


def decrypt_private(private_key, encrypted):
    return private_key.decrypt(
        encrypted,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None))


def get_message_and_signature(decrypted):
    len_first = int.from_bytes(decrypted[0:8], byteorder='big')
    message = decrypted[8:len_first + 8]
    signature = decrypted[len_first + 8:]
    return message, signature


def check_data_consistency(send_data, record_data):
    for send_key in send_data:
        if send_key not in record_data:
            return False
        if send_data[send_key] != record_data[send_key]:
            return False
    return True
