# jet-python
JSON Encrypted Token - Python module

```python
from jet import JET
from jet.utils import hmac_sha256


GLOBAL_JET = JET(
    SECRET = 'my-secret-string'
)

user_secret = hmac_sha256('user-password', 'user-password', 'ascii')

payload = {
    'id': 1,
    'message': "Hola"
}

# Generate token
token = GLOBAL_JET.encrypt(user_secret, payload)

# Get info on token
decrypted_meta, decrypted_payload = GLOBAL_JET.decrypt(user_secret, token)

```
