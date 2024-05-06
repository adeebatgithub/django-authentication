import os

from django.contrib.auth import get_user_model
from django.contrib.auth import login
from django.shortcuts import get_object_or_404
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.views import View
from django.conf import settings
from django.http import HttpResponseServerError
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

if settings.DEBUG:
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'


def get_flow(state=None):
    return Flow.from_client_secrets_file(
        settings.GOODLE_AUTH.get("client_secret_file"),
        scopes=settings.GOODLE_AUTH.get("scopes"),
        redirect_uri=settings.GOODLE_AUTH.get("redirect_uri"),
        state=state
    )


class GoogleLogin(View):

    def get(self, request):
        flow = get_flow()
        authorization_url, state = flow.authorization_url(
            access_type=settings.GOODLE_AUTH.get("access_type"),
            prompt='select_account')
        request.session['GOOGLE_AUTH_STATE'] = state
        return redirect(authorization_url)


class GoogleCallback(View):

    def get_user_info(self):
        flow = get_flow(state=self.request.GET.pop('GOOGLE_AUTH_STATE'))
        authorization_response = self.request.build_absolute_uri()
        flow.fetch_token(authorization_response=authorization_response)
        credentials = flow.credentials
        user_info_service = build('oauth2', 'v2', credentials=credentials)
        return user_info_service.userinfo().get().execute()

    def get(self, request, **kwargs):
        if request.GET.get('state') != request.session['GOOGLE_AUTH_STATE']:
            raise HttpResponseServerError("Invalid google auth state")

        user_info = self.get_user_info()
        request.session['GOOGLE_AUTH_USER_INFO'] = user_info
        return redirect(reverse_lazy("users:google-redirect"))


class GoogleRedirect(View):
    model = get_user_model()
    template_name = 'general/user-login.html'

    def user_exists(self, **kwargs):
        return self.model.objects.filter(**kwargs).exists()

    def get_user(self, **kwargs):
        return get_object_or_404(self.model, **kwargs)

    def login_user(self, user):
        login(self.request, user)
        return redirect(reverse_lazy('users:redirect-user'))

    def register_user(self, user_info):
        data = {
            'email': user_info['email'],
            'username': user_info['name'],
        }
        user = get_user_model().objects.create_user(**data)
        return self.login_user(user)

    def get(self, request, **kwargs):
        user_info = request.session.pop('GOOGLE_AUTH_USER_INFO')
        if self.user_exists(email=user_info.get('email')):
            user = self.get_user(email=user_info.get("email"))
            return self.login_user(user)
        else:
            return self.register_user(user_info)
