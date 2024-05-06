import os
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

from django.views import View, generic
from django.urls import reverse_lazy
from django.shortcuts import redirect
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate, login
from django.shortcuts import get_object_or_404

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
        print(state)
        return redirect(authorization_url)


class GoogleCallback(View):

    def get_user_info(self):
        flow = get_flow(state=self.request.GET.get('state'))
        authorization_response = self.request.build_absolute_uri()
        flow.fetch_token(authorization_response=authorization_response)
        credentials = flow.credentials
        user_info_service = build('oauth2', 'v2', credentials=credentials)
        return user_info_service.userinfo().get().execute()

    def get(self, request, **kwargs):
        if request.GET.get('state') != request.session['state']:
            raise Exception('Invalid state')
        user_info = self.get_user_info()
        request.session['user_info'] = user_info
        request.session['code'] = request.GET.get('code')
        return redirect(reverse_lazy("users:google-redirect"))


class GoogleRedirect(View):

    def user_exists(self, **kwargs):
        return get_user_model().objects.filter(**kwargs).exists()

    def get_user(self, **kwargs):
        return get_object_or_404(get_user_model(), **kwargs)

    def login_user(self, code):
        user = self.get_user()
        auth = authenticate(se)
        if auth:
            login(self.request, auth)
            return redirect(reverse_lazy('users:redirect-user'))

    def register_user(self, user_info):
        data = {
            'email': user_info['email'],
            'username': user_info['name'],
        }
        user = get_user_model().objects.create_user(**data)

    def get(self, request, **kwargs):
        user_info = request.session['user_info']
        print(user_info)
        if self.user_exists(username=user_info['name']):
            self.login_user()
        else:
            self.register_user(user_info)
