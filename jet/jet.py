import os
import json
from backports.pbkdf2 import pbkdf2_hmac
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from jet.exceptions import JETException
from jet.utils import (
    hmac_sha256,
    encode_dict,
    decode_dict,
    base64encode,
    base64decode,
    bytes_to_encoded_string,
    encoded_string_to_bytes
)


class JET:
    """
        JSON Encrypted Token
    """

    def __init__(
        self,
        SECRET,
        public_key = None,
        private_key = None,
        public_exponent = 65537,
        key_size = 2048,
        name = 'default',
        algorithm = 'sha256',
        iterations = 50000,
        derived_key_size = 64,
        encoding = 'ascii',
        exp = None,
        typ = 'JET-1'
    ):
        self.SECRET = SECRET
        self.public_exponent = public_exponent
        self.key_size = key_size
        self.name = name
        self.alg = algorithm
        self.iterations = iterations
        self.derived_key_size = derived_key_size
        self.encoding = encoding
        self.exp = exp
        self.typ = typ

        if public_key and private_key:
            self.public_key = public_key
            self.private_key = private_key
            self.key_size = None
            self.public_exponent = None
        else:
            self.generate_keys()

    def generate_keys(self):
        default_public_exponent = 65537
        default_key_size = 2048
        self.private_key = rsa.generate_private_key(
            public_exponent = self.public_exponent or default_public_exponent,
            key_size = self.key_size or default_key_size
        )
        self.public_key = self.private_key.public_key()

    def encrypt(self, user_secret, payload, exp=None):
        """
        user_secret could be some string derivated from user password (but not the password) because you must keep it on frontend
        while session is open to decrypt tokens asociated to that user
        Ex: user_secret = hmac_sha256(password, password)
              so you can reproduce this user_secret in frontend
        """

        salt = os.urandom(self.derived_key_size)
        derived_key = pbkdf2_hmac(
            self.alg,
            user_secret.encode(self.encoding),
            salt,
            self.iterations,
            self.derived_key_size
        )

        meta = {
            'rnd': self.random_string(),
            'typ': self.typ,
            'alg': self.alg,
            'ite': self.iterations,
            'siz': self.derived_key_size,
            'exp': exp or self.exp
        }

        payload['rnd'] = self.random_string()
        encrypted_payload = self.encrypt_payload(payload)
        encrypted_private_key = self.encrypt_private_key(derived_key)

        unsigned_token = '{encoded_meta}.{encrypted_payload}.{encrypted_private_key}.{salt}'.format(
            encoded_meta = encode_dict(meta, self.encoding),
            encrypted_payload = encrypted_payload,
            encrypted_private_key = encrypted_private_key,
            salt = bytes_to_encoded_string(salt, self.encoding)
        )

        sign = hmac_sha256(unsigned_token, self.SECRET, self.encoding)

        return '{unsigned_token}.{sign}'.format(
            unsigned_token = unsigned_token,
            sign = sign
        )

    def decrypt(self, user_secret, token):
        encoded_meta, encrypted_encoded_payload, encrypted_private_key, encoded_salt, sign = token.split('.')
        salt = encoded_string_to_bytes(encoded_salt)

        meta = decode_dict(encoded_meta, self.encoding)
        derived_key = pbkdf2_hmac(
            self.alg,
            user_secret.encode(self.encoding),
            salt,
            self.iterations,
            self.derived_key_size
        )
        private_key = self.decrypt_private_key(encrypted_private_key, derived_key)
        payload_bytes = self.decrypt_payload(encrypted_encoded_payload, private_key)
        encoded_payload = bytes_to_encoded_string(payload_bytes, self.encoding)
        payload = decode_dict(encoded_payload, self.encoding)

        return meta, payload

    def decrypt_from_PK(self, token):
        try:
            encoded_meta, encrypted_encoded_payload, encrypted_private_key, encoded_salt, sign = token.split('.')
            meta = decode_dict(encoded_meta, self.encoding)
            payload_bytes = self.decrypt_payload(encrypted_encoded_payload, self.private_key)
            encoded_payload = bytes_to_encoded_string(payload_bytes, self.encoding)
            payload = decode_dict(encoded_payload, self.encoding)
        except:
            raise JETException

        return meta, payload

    @property
    def plain_public_key(self):
        return bytes_to_encoded_string(
            self.public_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.PKCS1
            ),
            self.encoding
        )

    def encrypt_private_key(self, derived_key):
        # encrypt(self.private_key, derived_key)
        return bytes_to_encoded_string(
            self.private_key.private_bytes(
                encoding = serialization.Encoding.DER,
                format = serialization.PrivateFormat.PKCS8,
                encryption_algorithm = serialization.BestAvailableEncryption(derived_key)
                # encryption_algorithm = serialization.NoEncryption()
            ),
            self.encoding
        )

    def encrypt_payload(self, payload):
        # RSA_encrypt(payload, self.public_key)
        encrypted_payload = self.public_key.encrypt(
            encoded_string_to_bytes(
                encode_dict(payload, self.encoding)
            ),
            padding.OAEP(
                mgf = padding.MGF1(
                    algorithm = hashes.SHA256()
                ),
                algorithm = hashes.SHA256(),
                label = None
            )
        )
        return bytes_to_encoded_string(encrypted_payload, self.encoding)

    def decrypt_private_key(self, encrypted_private_key, derived_key):
        # decrypt(encrypted_private_key, derived_key)
        private_key = serialization.load_der_private_key(
            encoded_string_to_bytes(encrypted_private_key),
            password = derived_key
            # password = None
        )

        # print(isinstance(private_key, rsa.RSAPrivateKey))
        return private_key

    def decrypt_payload(self, encrypted_encoded_payload, private_key):
        # RSA_decrypt(encrypted_payload, private_key)
        encoded_payload = private_key.decrypt(
            encoded_string_to_bytes(encrypted_encoded_payload),
            padding.OAEP(
                mgf = padding.MGF1(
                    algorithm = hashes.SHA256(),
                ),
                algorithm = hashes.SHA256(),
                label = None
            )
        )
        return encoded_payload

    def random_string(self):
        return bytes_to_encoded_string(
            os.urandom(self.derived_key_size // 5),
            self.encoding
        )
