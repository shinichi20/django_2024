import unittest
import base64
import json
from unittest.mock import patch, MagicMock
from myinfo.security import (
    generate_code_verifier,
    generate_code_challenge,
    generate_client_assertion,
    generate_dpop_header,
    verify_jws,
    decrypt_jwe,
)


class TestSecurity(unittest.TestCase):

    def test_generate_code_verifier(self):
        """Test bahwa kode verifier yang dihasilkan memiliki panjang yang benar"""
        verifier = generate_code_verifier()
        self.assertIsInstance(verifier, str)
        self.assertTrue(43 <= len(verifier) <= 128)

    def test_generate_code_challenge(self):
        """Test bahwa code challenge sesuai dengan SHA256 hash dari verifier"""
        verifier = "testverifier1234567890"
        expected_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()
        ).decode().rstrip("=")

        challenge = generate_code_challenge(verifier)
        self.assertEqual(challenge, expected_challenge)

    @patch("myinfo.security.jwt.encode", return_value="mock_assertion")
    @patch("myinfo.security.datetime")
    def test_generate_client_assertion(self, mock_datetime, mock_jwt_encode):
        """Test bahwa client assertion dihasilkan dengan benar"""
        mock_datetime.datetime.utcnow.return_value.timestamp.return_value = 1000000

        private_key_mock = MagicMock()
        assertion = generate_client_assertion("client_id", "private_key_path")

        self.assertEqual(assertion, "mock_assertion")
        mock_jwt_encode.assert_called_once()

    @patch("myinfo.security.jwt.encode", return_value="mock_dpop_token")
    @patch("myinfo.security.uuid.uuid4", return_value="mock_uuid")
    @patch("myinfo.security.datetime")
    def test_generate_dpop_header(self, mock_datetime, mock_uuid, mock_jwt_encode):
        """Test bahwa header DPoP dihasilkan dengan benar"""
        mock_datetime.datetime.utcnow.return_value.timestamp.return_value = 1000000

        private_key_mock = MagicMock()
        dpop_header = generate_dpop_header("https://api.example.com", "GET", private_key_mock)

        self.assertEqual(dpop_header, "mock_dpop_token")
        mock_jwt_encode.assert_called_once()

    @patch("myinfo.security.jwt.decode", return_value={"sub": "mock_user"})
    @patch("myinfo.security.jwt.algorithms.RSAAlgorithm.from_jwk", return_value="mock_key")
    def test_verify_jws(self, mock_from_jwk, mock_decode):
        """Test bahwa JWS berhasil diverifikasi"""
        jwk_set = {"keys": [{"kid": "mock_kid", "kty": "RSA"}]}
        verified_data = verify_jws("mock_jws", jwk_set)

        self.assertEqual(verified_data, {"sub": "mock_user"})
        mock_decode.assert_called_once()

    @patch("myinfo.security.jose_jwe.decrypt", return_value=b'{"decrypted": "data"}')
    def test_decrypt_jwe(self, mock_decrypt):
        """Test bahwa JWE dapat didekripsi dengan benar"""
        private_key_mock = MagicMock()
        decrypted_data = decrypt_jwe("mock_jwe_token", private_key_mock)

        self.assertEqual(decrypted_data, {"decrypted": "data"})
        mock_decrypt.assert_called_once()


if __name__ == "__main__":
    unittest.main()
