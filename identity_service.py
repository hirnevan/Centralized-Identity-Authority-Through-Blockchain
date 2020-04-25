from user_data_action import UserDataAction
from user_data_share_action import UserDataShareAction
from transaction import Transaction
from util import decrypt, split_data, check_data_consistency
import json


# Represents the central identity authority
class IdentityService:
    transaction_pool = {}
    keys = {}
    latest_tx_list = {}

    last_transaction_hash = b'Base'

    def __init__(self):
        self.transaction_pool = {}
        self.keys = {}
        self.latest_tx_list = {}
        self.last_transaction_hash = b'Base'

    # adds a transaction to the blockchain
    def add_transaction_to_chain(self, tx, encryption_key=None):
        # save the transaction to the transaction pool
        self.transaction_pool[tx.get_hash()] = tx

        # Save the encryption key if the identity service encrypted
        # the data. This way we can decrypt it for comparisons later
        if encryption_key is not None:
            self.keys[tx.get_hash()] = encryption_key

        # Update the head of the chain
        self.last_transaction_hash = tx.get_hash()

        # Return the new transaction hash
        return self.last_transaction_hash

    # adds or updates user data
    def add_user_data(self, user_data, user_cert):
        # create a user data action
        user_action = UserDataAction(user_data)
        # get the encryption key to store it for later
        user_action_key = user_action.encryption_key

        # create the transaction
        transaction = Transaction(self.last_transaction_hash, user_action)
        # add the transaction to the blockchain
        tx_hash = self.add_transaction_to_chain(transaction,
                                                encryption_key=user_action_key)
        # update the pointer to the latest transaction for the user
        self.latest_tx_list[user_cert] = tx_hash

        # return the transaction hash
        return tx_hash

    def share_data(self, user_data, user_cert, service_provider_cert):
        # get the latest transaction for the user
        latest_tx_hash = self.latest_tx_list[user_cert]
        latest_tx = self.transaction_pool[latest_tx_hash]
        key = self.keys[latest_tx_hash]

        # get the action from the transaction and decrypt the data
        decrypted = decrypt(key, latest_tx.action.get_data())
        message, _signature = split_data(decrypted)

        # check that the data to share matches the data on record
        is_consistent = check_data_consistency(json.loads(user_data.data),
                                               json.loads(message))

        # if it is not consistent, do not add the action to a transaction
        if not is_consistent:
            return None

        # if it is consistent, create a user share action
        new_share_action = UserDataShareAction(
            user_data, service_provider_cert)
        # create a transaction for the action
        transaction = Transaction(self.last_transaction_hash,
                                  new_share_action)
        # add the transaction to the chain and return the hash pointer
        return self.add_transaction_to_chain(transaction)

    # Returns a transaction for a specified hash
    def get_transaction(self, tx_hash):
        return self.transaction_pool[tx_hash]

    # Returns an encryption key for a transaction.
    # Should only be used internally as this is the encryption
    # key for the identity service.
    def get_key(self, tx_hash):
        return self.keys[tx_hash]
