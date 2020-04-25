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
from util import decrypt, decrypt_private, get_message_and_signature

ident_service = IdentityService()


def get_private_key(path):
    with open(path) as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read().encode(), password=None, backend=default_backend())
    return private_key


def get_cert(path):
    with open(path) as cert_file:
        cert_string = cert_file.read()
        cert = x509.load_pem_x509_certificate(cert_string.encode(),
                                              default_backend())
    return cert, cert_string


user_1_private_key = get_private_key('certs/user_1.key')
user_1_cert, user_1_cert_string = get_cert('certs/user_1.crt')

sp_1_private_key = get_private_key('certs/sp_1.key')
sp_1_cert, sp_1_cert_string = get_cert('certs/sp_1.crt')

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

data_send = json.dumps({'first_name': 'Bob'})
signature_send = user_1_private_key.sign(
    data_send.encode(),
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
user_data_send = UserData(data_send.encode(), signature_send)

share_tx_hash = ident_service.share_data(user_data_send, user_1_cert_string,
                                         sp_1_cert)

share_tx = ident_service.get_share_transaction(share_tx_hash)
encrypted_encryption_key, encrypted_data = get_message_and_signature(
    share_tx.transaction.get_data())
decrypted_encryption_key = decrypt_private(sp_1_private_key,
                                           encrypted_encryption_key)
share_decrypted = decrypt(decrypted_encryption_key, encrypted_data)
share_message, share_signature = get_message_and_signature(share_decrypted)

user_1_cert.public_key().verify(
    share_signature, share_message,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

print(share_message)

print(message)
print(signature)
