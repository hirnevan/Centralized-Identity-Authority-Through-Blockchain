import json


# Represents user information
class UserData:
    data = None
    signature = None

    def __init__(self, data, signature):
        # Data is a json blob encoded to bytes
        self.data = data
        # This is the signature of the data by the user's private key
        self.signature = signature

    def to_bytes(self):
        return (len(self.data)).to_bytes(
            8, byteorder='big') + self.data + self.signature
