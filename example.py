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

token = GLOBAL_JET.encrypt(user_secret, payload)
print(token)

decrypted_meta, decrypted_payload = GLOBAL_JET.decrypt(user_secret, token)
print()
print(decrypted_meta)
print(decrypted_meta['rnd'])
print(decrypted_payload)
print(decrypted_payload['message'])

decrypted_meta, decrypted_payload = GLOBAL_JET.decrypt_from_PK(token)
print()
print(decrypted_meta)
print(decrypted_payload)

print()

verified_sign = GLOBAL_JET.is_valid_token(token)
print("Token is valid? ", verified_sign)

new_token = GLOBAL_JET.refresh_token(token)
print("Token == New Token ", token == new_token)
