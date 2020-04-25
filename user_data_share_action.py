import secrets
from util import encrypt_public, encrypt, combine_data


# Represents the action of a user sharing data with a service provider
class UserDataShareAction:
    tx_type = 'user_data_share_action'
    user_data = None

    def __init__(self, data, service_provider_cert):
        # generate a symmetric encryption key to encrypt the data
        encryption_key = secrets.token_bytes(32)

        # encrypt the symmetric encryption key with the public key of the receiver
        encrypted_encryption_key = encrypt_public(
            service_provider_cert.public_key(), encryption_key)

        # encrypt the user data with the generated symmetric key
        encrypted_data = encrypt(encryption_key, data.to_bytes())

        # combine the key and data to send to the service provider
        self.user_data = combine_data(encrypted_encryption_key, encrypted_data)

    def get_data(self):
        return self.user_data
