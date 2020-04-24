from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, hmac, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets
import json

class UserDataTransaction:
    tx_type = 'user_data_transaction'
    user_data = None
    encryption_key = None

    def __init__(self, data):
        self.encryption_key = secrets.token_bytes(32)

        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(data.to_bytes())
        padded_data += padder.finalize()

        cipher = Cipher(algorithms.AES(self.encryption_key),
                        modes.ECB(),
                        backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        self.user_data = encrypted_data
    
    def get_data(self):
        return self.user_data
