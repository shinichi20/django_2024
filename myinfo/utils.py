from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import jwt  # PyJWT harus diinstal

def decrypt_jwe(jwe_token):
    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

    decoded_token = jwt.decode(jwe_token, key=private_key, algorithms=["RS256"])
    return decoded_token
