import json


class UserData:
    data = None
    signature = None

    def __init__(self, data, signature):
        self.data = data
        self.signature = signature

    def to_bytes(self):
        return (len(self.data)).to_bytes(
            8, byteorder='big') + self.data + self.signature
