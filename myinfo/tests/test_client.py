import unittest
from unittest.mock import patch, MagicMock
from myinfo.client import MyInfoPersonalClientV4


class TestMyInfoPersonalClientV4(unittest.TestCase):

    def setUp(self):
        """Setup instance of MyInfoPersonalClientV4 before each test"""
        self.client = MyInfoPersonalClientV4()

    @patch("myinfo.client.settings")
    def test_get_url(self, mock_settings):
        """Test URL generation"""
        mock_settings.MYINFO_DOMAIN = "https://example.com"
        expected_url = "https://example.com/com/v4/person"
        self.assertEqual(self.client.get_url("person"), expected_url)

    @patch("myinfo.client.requests.Session.request")
    def test_request_successful(self, mock_request):
        """Test request method with successful response"""
        mock_request.return_value.status_code = 200
        mock_request.return_value.json.return_value = {"status": "ok"}

        response = self.client.request("https://example.com/api", method="GET")
        self.assertEqual(response, {"status": "ok"})

    @patch("myinfo.client.requests.Session.request")
    def test_request_http_error(self, mock_request):
        """Test request method with HTTP error"""
        mock_request.return_value.raise_for_status.side_effect = Exception("HTTP Error")

        with self.assertRaises(Exception):
            self.client.request("https://example.com/api", method="GET")

    @patch("myinfo.client.generate_code_challenge", return_value="mock_challenge")
    @patch("myinfo.client.settings")
    def test_get_authorise_url(self, mock_settings, mock_challenge):
        """Test authorisation URL generation"""
        mock_settings.MYINFO_CLIENT_ID = "test_client"
        mock_settings.MYINFO_SCOPE = "profile"
        mock_settings.MYINFO_PURPOSE_ID = "verify"
        callback_url = "https://app.example.com/callback"

        url = self.client.get_authorise_url("mock_state", callback_url)
        self.assertIn("client_id=test_client", url)
        self.assertIn("code_challenge=mock_challenge", url)
        self.assertIn("redirect_uri=https%3A//app.example.com/callback", url)

    @patch("myinfo.client.requests.Session.request")
    @patch("myinfo.client.generate_client_assertion", return_value="mock_assertion")
    @patch("myinfo.client.generate_dpop_header", return_value="mock_dpop")
    def test_get_access_token(self, mock_request, mock_assertion, mock_dpop):
        """Test getting access token"""
        mock_request.return_value.json.return_value = {"access_token": "mock_token"}

        response = self.client.get_access_token(
            auth_code="mock_auth_code",
            state="mock_state",
            callback_url="https://callback.example.com",
            session_ephemeral_keypair=MagicMock()
        )
        self.assertEqual(response["access_token"], "mock_token")

    @patch("myinfo.client.requests.Session.request")
    @patch("myinfo.client.verify_jws", return_value={"sub": "mock_user"})
    @patch("myinfo.client.get_jwkset")
    @patch("myinfo.client.generate_dpop_header", return_value="mock_dpop")
    def test_get_person_data(self, mock_request, mock_verify, mock_jwkset, mock_dpop):
        """Test getting person data"""
        mock_request.return_value.json.return_value = {"data": "mock_data"}

        response = self.client.get_person_data("mock_access_token", MagicMock())
        self.assertEqual(response, {"data": "mock_data"})

    @patch("myinfo.client.generate_ephemeral_session_keypair", return_value=MagicMock())
    @patch("myinfo.client.MyInfoPersonalClientV4.get_access_token", return_value={"access_token": "mock_token"})
    @patch("myinfo.client.MyInfoPersonalClientV4.get_person_data", return_value="encrypted_data")
    @patch("myinfo.client.decrypt_jwe", return_value={"decrypted": "data"})
    def test_retrieve_resource(self, mock_decrypt, mock_get_person, mock_get_token, mock_keypair):
        """Test full resource retrieval flow"""
        response = self.client.retrieve_resource(
            auth_code="mock_auth_code",
            state="mock_state",
            callback_url="https://callback.example.com"
        )
        self.assertEqual(response, {"decrypted": "data"})


if __name__ == "__main__":
    unittest.main()
