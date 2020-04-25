from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, hmac, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets
import json


class UserDataShareTransaction:
    tx_type = 'user_data_share_transaction'
    user_data = None

    def __init__(self, data, service_provider_cert):
        encryption_key = secrets.token_bytes(32)
        encrypted_encryption_key = service_provider_cert.public_key().encrypt(
            encryption_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(),
                         label=None))

        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(data.to_bytes())
        padded_data += padder.finalize()

        cipher = Cipher(algorithms.AES(encryption_key),
                        modes.ECB(),
                        backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        self.user_data = (len(encrypted_encryption_key)).to_bytes(
            8, byteorder='big') + encrypted_encryption_key + encrypted_data

    def get_data(self):
        return self.user_data
