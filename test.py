from user_data import UserData
from identity_service import IdentityService
from user_data_transaction import UserDataTransaction
from transaction import Transaction
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, hmac, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import json


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


ident_service = IdentityService()

with open('certs/user_1.key') as user_1_key_file:
    user_1_private_key = serialization.load_pem_private_key(
        user_1_key_file.read().encode(),
        password=None,
        backend=default_backend())

with open('certs/user_1.crt') as user_1_cert_file:
    user_1_cert_string = user_1_cert_file.read()
    user_1_cert = x509.load_pem_x509_certificate(user_1_cert_string.encode(),
                                                 default_backend())

data = json.dumps({'first_name': 'Bob', 'last_name': 'Smith'})

signature = user_1_private_key.sign(
    data.encode(),
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

user_data_1 = UserData(data.encode(), signature)

tx_hash = ident_service.add_user_data(user_data_1, user_1_cert_string)
tx, key = ident_service.get_transaction(tx_hash)

a = decrypt(key, tx.transaction.get_data())

len_first = int.from_bytes(a[0:8], byteorder='big')
message = a[8:len_first + 8]
signature = a[len_first + 8:]

is_valid = user_1_cert.public_key().verify(
    signature, message,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

print(message)
print(signature)
