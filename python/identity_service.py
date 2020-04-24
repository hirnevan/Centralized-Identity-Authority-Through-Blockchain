from user_data_transaction import UserDataTransaction
from transaction import Transaction

class IdentityService:
    transaction_pool = {}
    keys = {}

    last_transaction_hash = b'Base'

    def add_user_data(self, user_data):
        user_transaction = UserDataTransaction(user_data)
        user_transaction_key = user_transaction.encryption_key

        transaction = Transaction(self.last_transaction_hash, user_transaction)

        self.transaction_pool[transaction.get_hash()] = transaction
        self.keys[transaction.get_hash()] = user_transaction_key
        self.last_transaction_hash = transaction.get_hash()

        return self.last_transaction_hash

    def get_transaction(self, tx_hash):
        return self.transaction_pool[tx_hash], self.keys[tx_hash]
