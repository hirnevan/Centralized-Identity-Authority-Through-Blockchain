from util import compute_hash


# Represents a transaction in the blockchain
class Transaction:
    tx_hash = None
    hash_pointer = None
    action = None

    def __init__(self, previous_tx, action):
        self.tx_hash = None
        # Save the pointer to the previos head of the chain
        self.hash_pointer = previous_tx
        # Save the action for this transaction
        self.action = action

    def get_hash(self):
        # if the transaction hash has not yet been computed, compute it
        if self.tx_hash is None:
            # compute a hash based on the contents of the transaction
            self.tx_hash = compute_hash([
                self.hash_pointer,
                self.action.tx_type.encode(),
                self.action.get_data()
            ])
        # return the current transaction hash
        return self.tx_hash
