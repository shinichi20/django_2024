import base64
import json
import time
import logging
import requests
from hashlib import sha256
from django.utils.crypto import get_random_string
from jwcrypto import jwe, jwk, jws
from jwcrypto.jwk import JWK, JWKSet
from myinfo import settings as myinfo_settings

log = logging.getLogger(__name__)

class Security:
    @staticmethod
    def generate_code_challenge(code_verifier: str) -> str:
        log.info("Generating code challenge for verifier")
        try:
            code_verifier_hash = sha256(code_verifier.encode()).digest()
            challenge = base64.urlsafe_b64encode(code_verifier_hash).decode().replace("=", "")
            log.debug("Code challenge generated: %s", challenge)
            return challenge
        except Exception as e:
            log.error("Error generating code challenge: %s", str(e))
            raise

    @staticmethod
    def generate_ephemeral_session_keypair() -> JWK:
        log.info("Generating ephemeral session keypair...")
        return jwk.JWK.generate(kty="EC", crv="P-256", alg="ES256", use="sig")

    @staticmethod
    def generate_client_assertion(url: str, jkt_thumbprint: str) -> str:
        log.info("Generating client assertion for URL: %s", url)
        now = int(time.time())
        try:
            payload = {
                "sub": myinfo_settings.MYINFO_CLIENT_ID,
                "jti": get_random_string(40),
                "aud": url,
                "iss": myinfo_settings.MYINFO_CLIENT_ID,
                "iat": now,
                "exp": now + 300,
                "cnf": {"jkt": jkt_thumbprint},
            }
            jws_key = jwk.JWK.from_json(myinfo_settings.MYINFO_PRIVATE_KEY_SIG)
            jws_token = jws.JWS(json.dumps(payload))
            jws_token.add_signature(
                jws_key, alg=None, protected={"typ": "JWT", "alg": "ES256", "kid": jws_key.thumbprint()}
            )
            sig = json.loads(jws_token.serialize())
            log.debug("Client assertion successfully generated.")
            return f'{sig["protected"]}.{sig["payload"]}.{sig["signature"]}'
        except Exception as e:
            log.error("Error generating client assertion: %s", str(e))
            raise

    @staticmethod
    def generate_dpop_header(url: str, session_ephemeral_keypair, method="POST", ath=None) -> str:
        log.info("Generating DPoP header for URL: %s, method: %s", url, method)
        now = int(time.time())
        try:
            payload = {
                "htu": url,
                "htm": method,
                "jti": get_random_string(40),
                "iat": now,
                "exp": now + 120,
            }
            if ath:
                payload["ath"] = ath

            ephemeral_private_key = session_ephemeral_keypair.export_private()
            jwk_public = session_ephemeral_keypair.export_public(as_dict=True)
            jwk_public.update({"use": "sig", "alg": "ES256", "kid": session_ephemeral_keypair.thumbprint()})
            jws_key = jwk.JWK.from_json(ephemeral_private_key)
            jws_token = jws.JWS(json.dumps(payload))
            jws_token.add_signature(
                jws_key, alg=None, protected={"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk_public}
            )
            sig = json.loads(jws_token.serialize())
            log.debug("DPoP header successfully generated.")
            return f'{sig["protected"]}.{sig["payload"]}.{sig["signature"]}'
        except Exception as e:
            log.error("Error generating DPoP header: %s", str(e))
            raise

    @staticmethod
    def get_jwkset(key_url: str) -> JWKSet:
        log.info("Fetching JWK Set from URL: %s", key_url)
        try:
            response = requests.get(key_url, timeout=5)
            response.raise_for_status()
            keys_data = response.text
            log.debug("JWK Set fetched successfully.")
            return JWKSet.from_json(keys_data)
        except requests.RequestException as e:
            log.error("Error fetching JWK Set: %s", str(e))
            raise

    @staticmethod
    def verify_jws(raw_data: str, jwkset: JWKSet) -> dict:
        log.info("Verifying JWS token...")
        try:
            token = jws.JWS.from_jose_token(raw_data)
            token.verify(jwkset)
            payload = json.loads(token.payload.decode())
            log.debug("JWS token verified successfully.")
            return payload
        except Exception as e:
            log.error("JWS verification failed: %s", str(e))
            raise

    @staticmethod
    def decrypt_jwe(encrypted_data: str) -> dict:
        log.info("Decrypting JWE data...")
        try:
            jwe_key = jwk.JWK.from_json(myinfo_settings.MYINFO_PRIVATE_KEY_ENC)
            jwetoken = jwe.JWE()
            jwetoken.deserialize(encrypted_data, key=jwe_key)
            jwkset = Security.get_jwkset(myinfo_settings.MYINFO_JWKS_DATA_VERIFICATION_URL)
            decrypted_data = Security.verify_jws(jwetoken.payload.decode(), jwkset)
            log.debug("JWE successfully decrypted.")
            return decrypted_data
        except Exception as e:
            log.error("Error decrypting JWE: %s", str(e))
            raise
