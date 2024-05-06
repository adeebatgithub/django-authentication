import os
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

from django.views import View
from django.urls import reverse_lazy
from django.shortcuts import redirect

# Replace the client ID and client secret below with your own
CLIENT_ID = '1043779874380-pl4ultosv6ciig2pqv952jj8pftcl0b6.apps.googleusercontent.com'
CLIENT_SECRET_file = 'users/google_auth/client_secret.json'
SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]
REDIRECT_URI = 'http://127.0.0.1:8000/accounts/google/login/callback/'

# The authorization URL and redirect URL must match the ones you specified when you created the OAuth client ID
AUTH_URL = 'https://accounts.google.com/o/oauth2/auth'

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'


def get_flow(state=None):
    return Flow.from_client_secrets_file(
        CLIENT_SECRET_file,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
        state=state
    )

class GoogleLogin(View):

    def get(self, request):
        flow = get_flow()
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            prompt='select_account')

        # Save the state so we can verify the request later
        request.session['state'] = state
        return redirect(authorization_url)


class GoogleCallback(View):

    def get(self, request, **kwargs):
        # Verify the request state
        if request.GET.get('state') != request.session['state']:
            raise Exception('Invalid state')

        # Create the OAuth flow object
        flow = get_flow(state=request.GET.get('state'))

        # Exchange the authorization code for an access token
        authorization_response = request.build_absolute_uri()
        flow.fetch_token(authorization_response=authorization_response)

        # Save the credentials to the session
        credentials = flow.credentials

        user_info_service = build('oauth2', 'v2', credentials=credentials)
        user_info = user_info_service.userinfo().get().execute()
        print(user_info)

        return redirect(reverse_lazy("users:redirect-user"))
