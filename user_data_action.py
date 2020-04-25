import secrets
from util import encrypt


# Represents the action of a user adding or updating their data
class UserDataAction:
    tx_type = 'user_data_transaction'
    user_data = None
    encryption_key = None

    def __init__(self, data):
        # Generate an encryption key for the action
        self.encryption_key = secrets.token_bytes(32)
        # Encrypt the data
        encrypted_data = encrypt(self.encryption_key, data.to_bytes())
        # Save the encrypted data
        self.user_data = encrypted_data

    def get_data(self):
        return self.user_data
