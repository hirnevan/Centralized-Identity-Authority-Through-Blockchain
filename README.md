# Centralized Identity Authority Through Blockchain

## Setup

- `pip install cryptography`
- `pip install pytest`

## Running the tests

Run `pytest` in your shell - this should show the results from `test_service.py`

## Files

| File                      | Purpose |
| ------------------------- | ------- |
| certs/\*                  | Certificates and private keys used in the tests. |
| idenntity_service.py      | Represents the identity service. |
| test_service.py           | Runs test to validate the code. Gives examples of how the service is used. |
| transaction.py            | Represents a transaction in the blockchain. A transaction contains an action and a hash pointer to the previous transaction. |
| user_data_action.py       | Represents the action of a user uploading data to the identity service. |
| user_data_share_action.py | Represents the action of a user sharing data to a service provider. |
| user_data.py              | Wrapper around the data used in the user upload and share actions. |
| util.py                   | Utilities for encryption/decryption, hash generation, and other useful things used in the service and tests. |
