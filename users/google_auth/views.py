from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google_auth_oauthlib.flow import InstalledAppFlow

from django.views import View
from django.urls import reverse_lazy
from django.shortcuts import redirect

# Replace the client ID and client secret below with your own
CLIENT_ID = '1043779874380-pl4ultosv6ciig2pqv952jj8pftcl0b6.apps.googleusercontent.com'
CLIENT_SECRET_file = 'users/google_auth/client_secret.json'
SCOPES = [
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/userinfo.email"
]
REDIRECT_URI = 'http://127.0.0.1:8000/accounts/google/login/callback/'

# The authorization URL and redirect URL must match the ones you specified when you created the OAuth client ID
AUTH_URL = 'https://accounts.google.com/o/oauth2/auth'


class GoogleLogin(View):

    def get(self, request):
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRET_file, scopes=SCOPES)
        flow.redirect_uri = REDIRECT_URI
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
        flow = InstalledAppFlow.from_client_secrets_file(
            CLIENT_SECRET_file, scopes=SCOPES, state=request.session['state'])
        flow.redirect_uri = REDIRECT_URI

        # Exchange the authorization code for an access token
        authorization_response = request.GET.get('code')
        flow.fetch_token(authorization_response=authorization_response)

        # Save the credentials to the session
        credentials = flow.credentials
        print(credentials)
        # request.session['credentials'] = credentials_to_dict(credentials)

        return redirect(reverse_lazy("users:redirect-user"))
