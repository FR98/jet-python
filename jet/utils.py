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
    # Python dictionary to json
    return json.dumps(p_dict)

def encode_dict(p_dict, encoding):
    # Python dictionary to bytes string
    # Ex:
    #   In: {}
    #   Out: "ekjrnvecnsQ=="
    dict_string = stringfy_dict(p_dict)
    return base64encode(dict_string, encoding)

def decode_dict(encoded_dict, encoding):
    # Bytes string to python dictionary
    # Ex:
    #   In: "ekjrnvecnsQ=="
    #   Out: {}
    dict_string = encoded_string_to_bytes(encoded_dict)
    return json.loads(dict_string)

def base64encode(string, encoding):
    # String to bytes string
    # Ex:
    #   In: "blablabla"
    #   Out: "ekjrnvecnsQ=="
    string_bytes = string.encode(encoding)
    b64_bytes = base64.b64encode(string_bytes)
    b64_bytes_string = b64_bytes.decode(encoding)
    return b64_bytes_string

def base64decode(b64_bytes_string, encoding):
    # Bytes string to string
    # Ex:
    #   In: "ekjrnvecnsQ=="
    #   Out: "blablabla"
    b64_bytes = b64_bytes_string.encode(encoding)
    string_bytes = base64.b64decode(b64_bytes)
    string = string_bytes.decode(encoding)
    return string

def bytes_to_encoded_string(my_bytes, encoding):
    # Bytes string to string encoded
    # Ex:
    #   In: b'algo'
    #   Out: "ekjrnvecnsQ=="
    return base64.b64encode(my_bytes).decode(encoding)

def encoded_string_to_bytes(string):
    # String encoded to bytes string
    # Ex:
    #   In: "ekjrnvecnsQ=="
    #   Out: b'algo'
    return base64.b64decode(string)
