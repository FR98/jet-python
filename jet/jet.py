import json
import os
from backports.pbkdf2 import pbkdf2_hmac

from jet.utils import hmac_sha256, encode_dict
import jet.exceptions


class JET:
    """
        JSON Encrypted Token
    """

    def __init__(
        self,
        public_key,
        private_key,
        SECRET,
        name = 'default',
        algorithm = 'sha256',
        iterations = 50000,
        derived_key_size = 64,
        encoding = 'ascii',
        exp = None,
        typ = 'JET-1'
    ):
        self.public_key = public_key
        self.private_key = private_key
        self.SECRET = SECRET
        self.name = name
        self.alg = algorithm
        self.iterations = iterations
        self.derived_key_size = derived_key_size
        self.encoding = encoding
        self.typ = typ
        self.exp = exp

    def encrypt(self, user_secret, payload, exp=None):
        # user_secret could be some string derivated from user password (but not the password) because you must keep it on frontend
        # while session is open to decrypt tokens asociated to that user
        # Ex: user_secret = hmac_sha256(password, password)
        #       so you can reproduce this user_secret in frontend

        salt = os.urandom(64)
        derived_key = pbkdf2_hmac(self.alg, user_secret.encode(self.encoding), salt, self.iterations, self.derived_key_size)

        meta = {
            'alg': self.alg,
            'typ': self.typ,
            'exp': exp or self.exp
        }

        encrypted_payload = self.encrypt_payload(payload)
        encrypted_private_key = self.encrypt_private_key(derived_key)

        unsigned_token = '{encoded_meta}.{encrypted_payload}.{encrypted_private_key}.{salt}'.format(
            encoded_meta = encode_dict(meta, self.encoding),
            encrypted_payload = encrypted_payload,
            encrypted_private_key = encrypted_private_key,
            salt = salt
        )

        sign = hmac_sha256(unsigned_token, self.SECRET, self.encoding)

        return '{unsigned_token}.{sign}'.format(
            unsigned_token = unsigned_token,
            sign = sign
        )

    def decrypt(self, user_secret, token):
        encoded_meta, encrypted_payload, encrypted_private_key, salt, sign = token.split('.')

        derived_key = pbkdf2_hmac(self.alg, user_secret.encode(self.encoding), salt, self.iterations, self.derived_key_size)

        private_key = self.decrypt_private_key(encrypted_private_key, derived_key)
        payload = self.decrypt_payload(encrypted_payload, private_key)

        return payload

    # @property
    # def payload(self):
    #     pass

    def encrypt_private_key(self, derived_key):
        # AES_encrypt(self.private_key, derived_key)
        return 'encrypted-private-key'

    def encrypt_payload(self, payload):
        # RSA_encrypt(payload, self.public_key)
        encoded_payload = encode_dict(payload, self.encoding)
        return encoded_payload

    def decrypt_private_key(self, encrypted_private_key, derived_key):
        # AES_decrypt(encrypted_private_key, derived_key)
        return 'dencrypted-private-key'

    def decrypt_payload(self, encrypted_payload, private_key):
        # RSA_decrypt(encrypted_payload, private_key)
        # encoded_payload = encode_dict(payload, self.encoding)
        return 'dencrypted-encoded-payload'
