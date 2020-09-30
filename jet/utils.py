import hmac
import hashlib
import json
import base64

def hmac_sha256(msg, key, encoding):
    return hmac.new(
        msg = bytes(str(msg), encoding),
        key = bytes(str(key), encoding),
        digestmod = hashlib.sha256
    ).hexdigest()

def stringfy_dict(p_dict):
    return json.dumps(p_dict)

def encode_dict(p_dict, encoding):
    dict_string = stringfy_dict(p_dict)
    return base64encode(dict_string, encoding)

def base64encode(string, encoding):
    string_bytes = string.encode(encoding)
    b64_bytes = base64.b64encode(string_bytes)
    b64_bytes_string = b64_bytes.decode(encoding)
    return b64_bytes_string

def base64decode(b64_bytes_string, encoding):
    b64_bytes = b64_bytes_string.encode(encoding)
    string_bytes = base64.b64decode(b64_bytes)
    string = string_bytes.decode(encoding)
    return string

def salt_to_encoded_string(salt, encoding):
    return base64.b64encode(salt).decode(encoding)

def encoded_string_to_salt(string, encoding):
    return base64.b64decode(string).encode(encoding)
