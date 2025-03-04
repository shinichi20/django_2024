import base64
import logging
from hashlib import sha256
from json import JSONDecodeError
from urllib.parse import quote, urlencode

import requests
from myinfo import settings
from myinfo.security import (
    decrypt_jwe,
    generate_client_assertion,
    generate_code_challenge,
    generate_dpop_header,
    generate_ephemeral_session_keypair,
    get_jwkset,
    verify_jws,
)

# Konfigurasi Logger
logging.basicConfig(
    filename="client_errors.log",  # Simpan log ke file
    level=logging.ERROR,  # Log error dan level lebih tinggi
    format="%(asctime)s - %(levelname)s - %(message)s",  # Format log
)

log = logging.getLogger(__name__)  # Buat logger khusus untuk modul ini


class MyInfoClient:

    API_TIMEOUT = 30

    def __init__(self, context, version, client_id, purpose_id):
        self.session = requests.Session()
        self.context = context
        self.version = version
        self.client_id = client_id
        self.purpose_id = purpose_id

    def get_url(self, resource: str) -> str:
        return f"{settings.MYINFO_DOMAIN}/{self.context}/{self.version}/{resource}"

    def request(self, api_url, method="GET", headers=None, params=None, data=None):
        headers = headers or {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }

        try:
            response = self.session.request(
                method,
                url=api_url,
                params=params,
                data=data,
                timeout=self.API_TIMEOUT,
                verify=settings.CERT_VERIFY,
                headers=headers,
            )
            response.raise_for_status()
            return response.json()
        except requests.HTTPError as e:
            log.error("HTTPError saat request ke %s: %s", api_url, e.response.text)
            raise
        except JSONDecodeError:
            log.error("JSONDecodeError saat parsing response dari %s", api_url)
            return response.text
        except requests.RequestException as e:
            log.error("RequestException saat request ke %s: %s", api_url, str(e))
            raise


class MyInfoPersonalClientV4(MyInfoClient):

    def __init__(self):
        super().__init__("com", "v4", settings.MYINFO_CLIENT_ID, settings.MYINFO_PURPOSE_ID)

    def get_retrieve_resource_url(self, sub: str) -> str:
        return f"{self.get_url('person')}/{sub}/"

    def get_authorise_url(self, oauth_state: str, callback_url: str) -> str:
        query = {
            "client_id": self.client_id,
            "scope": settings.MYINFO_SCOPE,
            "purpose_id": self.purpose_id,
            "response_type": "code",
            "code_challenge": generate_code_challenge(oauth_state),
            "code_challenge_method": "S256",
            "redirect_uri": callback_url,
        }
        return f"{self.get_url('authorize')}?{urlencode(query, safe=',/:', quote_via=quote)}"

    def get_access_token(self, auth_code: str, state: str, callback_url: str, keypair=None):
        api_url = self.get_url("token")
        keypair = keypair or generate_ephemeral_session_keypair()
        client_assertion = generate_client_assertion(api_url, keypair.thumbprint())

        data = {
            "code": auth_code,
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "redirect_uri": callback_url,
            "client_assertion": client_assertion,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "code_verifier": state,
        }

        headers = {
            "DPoP": generate_dpop_header(api_url, keypair),
            "Cache-Control": "no-cache",
        }

        try:
            return self.request(api_url, method="POST", headers=headers, data=data)
        except Exception as e:
            log.error("Gagal mendapatkan access token: %s", str(e))
            raise

    def get_person_data(self, access_token: str, keypair):
        try:
            jwkset = get_jwkset(settings.MYINFO_JWKS_TOKEN_VERIFICATION_URL)
            decoded_token = verify_jws(access_token, jwkset)
            api_url = self.get_retrieve_resource_url(decoded_token["sub"])

            access_token_hash = sha256(access_token.encode()).digest()
            ath = base64.urlsafe_b64encode(access_token_hash).decode().replace("=", "")

            headers = {
                "Authorization": f"DPoP {access_token}",
                "dpop": generate_dpop_header(api_url, keypair, method="GET", ath=ath),
                "Cache-Control": "no-cache",
            }

            return self.request(api_url, method="GET", headers=headers, params={"scope": settings.MYINFO_SCOPE})
        except Exception as e:
            log.error("Gagal mendapatkan data person: %s", str(e))
            raise

    def retrieve_resource(self, auth_code: str, state: str, callback_url: str) -> dict:
        try:
            keypair = generate_ephemeral_session_keypair()
            access_token_resp = self.get_access_token(auth_code, state, callback_url, keypair)
            access_token = access_token_resp["access_token"]
            person_data = self.get_person_data(access_token, keypair)

            return decrypt_jwe(person_data)
        except Exception as e:
            log.error("Gagal retrieve resource: %s", str(e))
            raise
