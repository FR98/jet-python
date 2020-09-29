import hmac
import hashlib
import json

def hmac_sha256(msg, key, encoding):
    return hmac.new(
        msg = bytes(str(msg), encoding),
        key = bytes(str(key), encoding),
        digestmod = hashlib.sha256
    ).hexdigest()

def encode_dict(p_dict, encoding):
    return json.dumps(p_dict).encode(encoding)
