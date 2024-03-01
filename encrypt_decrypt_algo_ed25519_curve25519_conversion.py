#Encryption and Decryption of Messages

```
GENERATE AN ALGORAND PRIVATE KEY AND PRIVATE KEY
from algosdk import account

private_key, public_key = account.generate_account()
print(private_key, public_key)
```

from algosdk import encoding, mnemonic
from nacl.public import PrivateKey, PublicKey, Box
from nacl.bindings import crypto_sign_ed25519_pk_to_curve25519, crypto_sign_ed25519_sk_to_curve25519
import base64

sender_private_key_base64 = 'RC2jz1ANegLX5ShUbhuXySgKyrNY86kLP43JUG8HaIJ/IMWtmWrQPjJFlrTuNb3EqSBnZc65JpoFAceqCfN/3w=='
sender_public_key_encoded = 'P4QMLLMZNLID4MSFS22O4NN5YSUSAZ3FZ24SNGQFAHD2UCPTP7P3VDXODQ'
sender_public_key_bytes = encoding.decode_address(sender_public_key_encoded)
sender_private_key_bytes = mnemonic._to_key(mnemonic.from_private_key(sender_private_key_base64)) + sender_public_key_bytes
sender_curve25519_private_key_bytes = crypto_sign_ed25519_sk_to_curve25519(sender_private_key_bytes)
sender_curve25519_public_key_bytes = crypto_sign_ed25519_pk_to_curve25519(sender_public_key_bytes)
sender_private_key_class = PrivateKey(sender_curve25519_private_key_bytes)
sender_public_key_class = PublicKey(sender_curve25519_public_key_bytes)

receiver_private_key_base64 = '++BbBwXDkcIwnKWBIj9tGzApMjmSKFTPcGiQwxMNVb3kKQDRoR+aY8UatfphKDora3D760hRX0Y+Rd8K9wLIVw=='
receiver_public_key_encoded = '4QUQBUNBD6NGHRI2WX5GCKB2FNVXB67LJBIV6RR6IXPQV5YCZBLTGQAIRI'
receiver_public_key_bytes = encoding.decode_address(receiver_public_key_encoded)
receiver_private_key_bytes = mnemonic._to_key(mnemonic.from_private_key(receiver_private_key_base64)) + receiver_public_key_bytes
receiver_curve25519_private_key_bytes = crypto_sign_ed25519_sk_to_curve25519(receiver_private_key_bytes)
receiver_curve25519_public_key_bytes = crypto_sign_ed25519_pk_to_curve25519(receiver_public_key_bytes)
receiver_private_key_class = PrivateKey(receiver_curve25519_private_key_bytes)
receiver_public_key_class = PublicKey(receiver_curve25519_public_key_bytes)

message = "This is a secret message for the sender and receiver only"
print(f'Message: {message}')
encoded_message = message.encode()
sender_box = Box(sender_private_key_class, receiver_public_key_class)
encrypted_message = sender_box.encrypt(encoded_message)
print("Encrypted Message:", base64.b64encode(encrypted_message).decode())

receiver_box = Box(receiver_private_key_class, sender_public_key_class)
decrypted_message = receiver_box.decrypt(encrypted_message)
print("Decrypted message:", decrypted_message.decode())
