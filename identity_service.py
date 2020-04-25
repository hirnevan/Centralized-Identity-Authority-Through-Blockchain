from user_data_transaction import UserDataTransaction
from user_data_share_transaction import UserDataShareTransaction
from transaction import Transaction
from util import decrypt, get_message_and_signature, check_data_consistency
import json


class IdentityService:
    transaction_pool = {}
    keys = {}
    latest_tx_list = {}

    last_transaction_hash = b'Base'

    def add_transaction_to_chain(self, tx, encryption_key=None):
        self.transaction_pool[tx.get_hash()] = tx
        if encryption_key is not None:
            self.keys[tx.get_hash()] = encryption_key
        self.last_transaction_hash = tx.get_hash()
        return self.last_transaction_hash

    def add_user_data(self, user_data, public_key):
        user_transaction = UserDataTransaction(user_data)
        user_transaction_key = user_transaction.encryption_key

        transaction = Transaction(self.last_transaction_hash, user_transaction)

        self.latest_tx_list[public_key] = transaction.get_hash()

        return self.add_transaction_to_chain(
            transaction, encryption_key=user_transaction_key)

    def share_data(self, user_data, user_cert, service_provider_cert):
        latest_tx_hash = self.latest_tx_list[user_cert]
        latest_tx = self.transaction_pool[latest_tx_hash]
        key = self.keys[latest_tx_hash]

        decrypted = decrypt(key, latest_tx.transaction.get_data())

        message, _signature = get_message_and_signature(decrypted)

        is_consistent = check_data_consistency(json.loads(user_data.data),
                                               json.loads(message))

        if not is_consistent:
            return None

        new_share_transaction = UserDataShareTransaction(
            user_data, service_provider_cert)

        transaction = Transaction(self.last_transaction_hash,
                                  new_share_transaction)

        return self.add_transaction_to_chain(transaction)

    def get_transaction(self, tx_hash):
        return self.transaction_pool[tx_hash], self.keys[tx_hash]

    def get_share_transaction(self, tx_hash):
        return self.transaction_pool[tx_hash]
