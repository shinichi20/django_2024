import requests
import os
from django.http import JsonResponse
from django.shortcuts import redirect

MYINFO_AUTH_URL = f"{os.getenv('MYINFO_API_URL')}/authorise"
MYINFO_TOKEN_URL = f"{os.getenv('MYINFO_API_URL')}/token"

def myinfo_login(request):
    """
    Redirect user to MyInfo authorization URL
    """
    auth_url = f"{MYINFO_AUTH_URL}?client_id={os.getenv('MYINFO_CLIENT_ID')}&redirect_uri={os.getenv('MYINFO_REDIRECT_URI')}&scope=openid&response_type=code"
    return redirect(auth_url)

def myinfo_callback(request):
    """
    Handle OAuth callback from MyInfo
    """
    auth_code = request.GET.get("code")
    if not auth_code:
        return JsonResponse({"error": "Authorization code not found"}, status=400)

    # Exchange auth code for access token
    token_response = requests.post(
        MYINFO_TOKEN_URL,
        data={
            "code": auth_code,
            "client_id": os.getenv("MYINFO_CLIENT_ID"),
            "client_secret": os.getenv("MYINFO_CLIENT_SECRET"),
            "redirect_uri": os.getenv("MYINFO_REDIRECT_URI"),
            "grant_type": "authorization_code",
        }
    )

    token_data = token_response.json()
    return JsonResponse(token_data)
