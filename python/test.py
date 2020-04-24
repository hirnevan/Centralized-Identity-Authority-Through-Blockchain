from user_data import UserData
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


with open('certs/user_1.key') as user_1_key_file:
    user_1_private_key = serialization.load_pem_private_key(
        user_1_key_file.read().encode(),
        password=None,
        backend=default_backend())

with open('certs/user_1.crt') as user_1_cert_file:
    user_1_cert_string = user_1_cert_file.read()
    user_1_cert = x509.load_pem_x509_certificate(user_1_cert_string.encode(),
                                                 default_backend())

transaction_pool = {}
keys = {}

data = json.dumps({'first_name': 'Bob', 'last_name': 'Smith'})

signature = user_1_private_key.sign(
    data.encode(),
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

user_data_1 = UserData(data.encode(), signature)

user_transaction_1 = UserDataTransaction(user_data_1)
user_transaction_1_key = user_transaction_1.encryption_key

transaction_1 = Transaction(b'Base', user_transaction_1)

transaction_pool[transaction_1.get_hash()] = transaction_1
keys[transaction_1.get_hash()] = user_transaction_1_key

# user_data_2 = UserData({'first_name': 'Sally', 'last_name': 'Smith'})
# user_transaction_2 = UserDataTransaction(user_data_2)
# transaction_2 = Transaction(transaction_1.get_hash(), user_transaction_2)

# transaction_pool[transaction_2.get_hash()] = transaction_2
# keys[transaction_2.get_hash()] = user_transaction_2.encryption_key

hash_pointer = transaction_1.get_hash()

a = decrypt(keys[hash_pointer],
            transaction_pool[hash_pointer].transaction.get_data())

len_first = int.from_bytes(a[0:8], byteorder='big')
message = a[8:len_first + 8]
signature = a[len_first + 8:]

is_valid = user_1_cert.public_key().verify(
    signature, message,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

print(message)
print(signature)
