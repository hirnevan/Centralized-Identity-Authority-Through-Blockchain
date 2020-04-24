from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


class Transaction:
    hash = None
    hash_pointer = None
    transaction = None

    def __init__(self, previous_tx, tx):
        self.hash_pointer = previous_tx
        self.transaction = tx

    def get_hash(self):
        if self.hash is None:
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(self.hash_pointer)
            digest.update(self.transaction.tx_type.encode())
            digest.update(self.transaction.get_data())
            self.hash = digest.finalize()
        return self.hash
