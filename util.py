from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, hmac, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# Symmetric decryption using AES
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


# Asymmetric decryption using RSA private key
def decrypt_private(private_key, encrypted):
    return private_key.decrypt(
        encrypted,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None))


# Assymetric encryption using RSA public key
def encrypt_public(public_key, data):
    return public_key.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None))


# Symmetric encryption using AES
def encrypt(encrypt_key, data):
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(data)
    padded_data += padder.finalize()

    cipher = Cipher(algorithms.AES(encrypt_key),
                    modes.ECB(),
                    backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()


# Assymetric signing using RSA public key
def sign(private_key, data):
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())


# Verify data based on signature.
# Throws error on invalid signature.
# Returns nothing otherwise.
def verify(cert, data, signature):
    cert.public_key().verify(
        signature, data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())


# Compute a hash based on an array of byte strings
def compute_hash(data_array):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    for data in data_array:
        digest.update(data)
    return digest.finalize()


# Combine two byte strings into one.
# The first 8 bytes will be the length of the first bytes string.
def combine_data(first, second):
    return (len(first)).to_bytes(8, byteorder='big') + first + second


# Split a byte string into two byte strings.
# The first 8 bytes determine the size of the first byte string.
def split_data(data):
    len_first = int.from_bytes(data[0:8], byteorder='big')
    first = data[8:len_first + 8]
    second = data[len_first + 8:]
    return first, second


# Checks that the data a users wants to send exists in
# the latest user record.
def check_data_consistency(send_data, record_data):
    # For each key in the data the user wants to send
    for send_key in send_data:
        # Check that the key exists in the latest user record
        if send_key not in record_data:
            return False
        # and that the data for that key is the same in both records
        if send_data[send_key] != record_data[send_key]:
            return False
    return True


# Helper for loading a private key from a key file.
def get_private_key(path):
    with open(path) as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read().encode(), password=None, backend=default_backend())
    return private_key


# Helper for loading a certificate from a crt file.
def get_cert(path):
    with open(path) as cert_file:
        cert_string = cert_file.read()
        cert = x509.load_pem_x509_certificate(cert_string.encode(),
                                              default_backend())
    return cert, cert_string
