import pytest
from util import sign, get_private_key, get_cert, split_data, verify, decrypt, decrypt_private
from user_data import UserData
from identity_service import IdentityService
import json


@pytest.fixture
def ident_service():
    yield IdentityService()


user_1_private_key = get_private_key('certs/user_1.key')
user_1_cert, user_1_cert_string = get_cert('certs/user_1.crt')

user_2_private_key = get_private_key('certs/user_2.key')
user_2_cert, user_2_cert_string = get_cert('certs/user_2.crt')

sp_1_private_key = get_private_key('certs/sp_1.key')
sp_1_cert, sp_1_cert_string = get_cert('certs/sp_1.crt')


# Test to ensure a user can add data to the service
def test_add_user_data(ident_service):
    # No transactions in the chain yet
    assert ident_service.last_transaction_hash == b'Base'

    # Create the data and signature
    data = json.dumps({'first_name': 'Bob', 'last_name': 'Smith'}).encode()
    signature = sign(user_1_private_key, data)
    user_data = UserData(data, signature)

    # Add the data to the service
    tx_hash = ident_service.add_user_data(user_data, user_1_cert_string)

    # Ensure the head of the chain is the new transaction
    assert tx_hash == ident_service.last_transaction_hash

    # Get the transaction and encryption key
    tx = ident_service.get_transaction(tx_hash)
    key = ident_service.get_key(tx_hash)

    # Ensure the transaction points to the old head of the chain
    assert tx.hash_pointer == b'Base'

    # Get the message and signature from the transaction
    decrypted = decrypt(key, tx.action.get_data())
    message, signature = split_data(decrypted)

    # Ensure the data has not been tampered with
    verify(user_1_cert, message, signature)

    # Ensure the data matches what the user uploaded
    assert message == data


# Test to ensure a user can update their data in the service
def test_edit_user_data(ident_service):
    # Ensure the head of the chain and the latest tx for the user are
    # in their initial states
    assert ident_service.latest_tx_list.get(user_1_cert_string) is None
    assert ident_service.last_transaction_hash == b'Base'

    # Create the initial data for the user
    data_1 = json.dumps({'first_name': 'Bob', 'last_name': 'Smith'}).encode()
    signature_1 = sign(user_1_private_key, data_1)
    initial_user_data = UserData(data_1, signature_1)

    # Add the user data to the service
    initial_tx_hash = ident_service.add_user_data(initial_user_data,
                                                  user_1_cert_string)

    # Ensure the head of the chain and the latest tx hash for the user
    # have been updated
    assert initial_tx_hash == ident_service.latest_tx_list[user_1_cert_string]
    assert initial_tx_hash == ident_service.last_transaction_hash

    # Get the transaction from the service
    initial_tx = ident_service.get_transaction(initial_tx_hash)

    # Ensure the transaction points to the old head of the chain
    assert initial_tx.hash_pointer == b'Base'

    # Create the updated data for the user
    data_2 = json.dumps({
        'first_name': 'Bob',
        'last_name': 'Smith',
        'age': 35
    }).encode()
    signature_2 = sign(user_1_private_key, data_2)
    updated_user_data = UserData(data_2, signature_2)

    # Add the updated data to the service
    updated_tx_hash = ident_service.add_user_data(updated_user_data,
                                                  user_1_cert_string)

    # Ensure the head of the chain and the latest tx hash for the user
    # have been updated
    assert updated_tx_hash == ident_service.latest_tx_list[user_1_cert_string]
    assert updated_tx_hash == ident_service.last_transaction_hash

    # Get the new transaction
    updated_tx = ident_service.get_transaction(updated_tx_hash)

    # Ensure the new transaction points at the previous head of the chain
    assert updated_tx.hash_pointer == initial_tx_hash


# Test to ensure a user can share data to a service provider
def test_share_data(ident_service):
    # Create the user data
    data = json.dumps({'first_name': 'Bob', 'last_name': 'Smith'}).encode()
    signature = sign(user_1_private_key, data)
    user_data = UserData(data, signature)

    # Add the user's data to the service
    tx_hash = ident_service.add_user_data(user_data, user_1_cert_string)

    # Create data to share with the service provider
    shared_data = json.dumps({'first_name': 'Bob'}).encode()
    signature = sign(user_1_private_key, shared_data)
    shared_user_data = UserData(shared_data, signature)

    # Add the shared data to the identity service
    shared_tx_hash = ident_service.share_data(shared_user_data,
                                              user_1_cert_string, sp_1_cert)

    # Ensure the head of the chain is the new transaction
    assert ident_service.last_transaction_hash == shared_tx_hash

    # Get the share transaction
    share_tx = ident_service.get_transaction(shared_tx_hash)

    # Ensure the share transaction points to the previous head of the chain
    assert tx_hash == share_tx.hash_pointer

    # As the service provider, get the encryption key and decrypt the data
    encrypted_encryption_key, encrypted_data = split_data(
        share_tx.action.get_data())
    decrypted_encryption_key = decrypt_private(sp_1_private_key,
                                               encrypted_encryption_key)
    share_decrypted = decrypt(decrypted_encryption_key, encrypted_data)
    share_message, share_signature = split_data(share_decrypted)

    # Verify the data is signed by the user and hasn't been tampered with
    verify(user_1_cert, share_message, share_signature)

    # Ensure the data matches what the user uploaded to the service
    assert share_message == shared_data


# Test that shared data still works even after a user edits their data
def test_add_share_edit(ident_service):
    # Create the initial user data
    data = json.dumps({'first_name': 'Bob', 'last_name': 'Smith'}).encode()
    signature = sign(user_1_private_key, data)
    user_data = UserData(data, signature)

    # Add the user data to the service
    initial_tx_hash = ident_service.add_user_data(user_data,
                                                  user_1_cert_string)

    # Create data to share with the service provider
    shared_data = json.dumps({'first_name': 'Bob'}).encode()
    signature = sign(user_1_private_key, shared_data)
    shared_user_data = UserData(shared_data, signature)

    # Add the shared data to the identity service
    shared_tx_hash = ident_service.share_data(shared_user_data,
                                              user_1_cert_string, sp_1_cert)

    # Ensure the head of the chain has been updated
    assert ident_service.last_transaction_hash == shared_tx_hash

    # Create updated user data
    data_2 = json.dumps({
        'first_name': 'Robert',
        'last_name': 'Smith',
        'age': 35
    }).encode()
    signature_2 = sign(user_1_private_key, data_2)
    updated_user_data = UserData(data_2, signature_2)

    # Update the user's data on the identity service
    updated_tx_hash = ident_service.add_user_data(updated_user_data,
                                                  user_1_cert_string)

    # Ensure the head of the chain has been updated
    assert updated_tx_hash == ident_service.latest_tx_list[user_1_cert_string]
    # Ensure the user's latest hash has been updated
    assert updated_tx_hash == ident_service.last_transaction_hash

    # Get the updated data transaction
    updated_tx = ident_service.get_transaction(updated_tx_hash)

    # Ensure the transaction points to the previous head of the chain
    assert updated_tx.hash_pointer == shared_tx_hash

    # Get the share transaction
    share_tx = ident_service.get_transaction(shared_tx_hash)

    # Ensure the share transaction points to the initial user data transaction
    assert initial_tx_hash == share_tx.hash_pointer

    # As the service provider, get the message and signature from the transaction
    encrypted_encryption_key, encrypted_data = split_data(
        share_tx.action.get_data())
    decrypted_encryption_key = decrypt_private(sp_1_private_key,
                                               encrypted_encryption_key)
    share_decrypted = decrypt(decrypted_encryption_key, encrypted_data)
    share_message, share_signature = split_data(share_decrypted)

    # Ensure the data is valid
    verify(user_1_cert, share_message, share_signature)

    # Ensure the data matches what the user uploaded at the time of
    # creating the share transaction and not the new user data.
    assert share_message == shared_data


# Ensure the service supports multiple users
def test_multiple_users(ident_service):
    assert ident_service.last_transaction_hash == b'Base'

    # Create the first user's data
    data_1 = json.dumps({'first_name': 'Bob', 'last_name': 'Smith'}).encode()
    signature_1 = sign(user_1_private_key, data_1)
    user_data = UserData(data_1, signature_1)

    # Add the first user's data to the identity service
    user_1_tx_hash = ident_service.add_user_data(user_data, user_1_cert_string)

    # Ensure the head of the chain has been updated
    assert user_1_tx_hash == ident_service.last_transaction_hash

    # Create the second user's data
    data_2 = json.dumps({'first_name': 'Sally', 'last_name': 'Jones'}).encode()
    signature_2 = sign(user_2_private_key, data_2)
    user_data_2 = UserData(data_2, signature_2)

    # Add the second user's data to the identity service
    user_2_tx_hash = ident_service.add_user_data(user_data_2,
                                                 user_2_cert_string)

    # Ensure the head of the chain has been updated
    assert user_2_tx_hash == ident_service.last_transaction_hash

    # Get the first user's transaction
    user_1_tx = ident_service.get_transaction(user_1_tx_hash)
    key_1 = ident_service.get_key(user_1_tx_hash)

    # Ensure the first user's transaction points to the base hash pointer
    assert user_1_tx.hash_pointer == b'Base'

    # Decrypt the first user's data
    decrypted_1 = decrypt(key_1, user_1_tx.action.get_data())
    message_1, signature_1 = split_data(decrypted_1)

    # Validate the first user's data
    verify(user_1_cert, message_1, signature_1)

    # Ensure the data from the transaction matches the data the first
    # user uploaded
    assert message_1 == data_1

    # Get the second user's transaction
    user_2_tx = ident_service.get_transaction(user_2_tx_hash)
    key_2 = ident_service.get_key(user_2_tx_hash)

    # Ensure the second user's transaction points to the first user's
    # transaction
    assert user_2_tx.hash_pointer == user_1_tx_hash

    # Decrypt the second user's transaction
    decrypted_2 = decrypt(key_2, user_2_tx.action.get_data())
    message_2, signature_2 = split_data(decrypted_2)

    # Validate the second user's data
    verify(user_2_cert, message_2, signature_2)

    # Ensure the data from the transaction matches the data that the
    # second user uploaded to the identity service
    assert message_2 == data_2

    # Ensure the latest transaction hash for the first and second
    # user match what we expect.
    assert ident_service.latest_tx_list[user_1_cert_string] == user_1_tx_hash
    assert ident_service.latest_tx_list[user_2_cert_string] == user_2_tx_hash
