from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth import login
from django.contrib.auth.models import Group
from django.http import HttpResponseServerError
from django.shortcuts import get_object_or_404
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.views import View
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from django.core.exceptions import ImproperlyConfigured


def get_flow(state=None):
    return Flow.from_client_secrets_file(
        settings.GOOGLE_AUTH.get("client_secret_file"),
        scopes=settings.GOOGLE_AUTH.get("scopes"),
        redirect_uri=settings.GOOGLE_AUTH.get("redirect_uri"),
        state=state
    )


class GoogleLogin(View):

    def get(self, request):
        if not hasattr(settings, 'GOOGLE_AUTH'):
            raise ImproperlyConfigured("GOOGLE_AUTH is not configured")

        flow = get_flow()
        authorization_url, state = flow.authorization_url(
            access_type=settings.GOOGLE_AUTH.get("access_type"),
            prompt='select_account')
        request.session['GOOGLE_AUTH_STATE'] = state
        return redirect(authorization_url)


class GoogleCallback(View):

    def get_user_info(self):
        flow = get_flow(state=self.request.GET.get('GOOGLE_AUTH_STATE'))
        authorization_response = self.request.build_absolute_uri()
        flow.fetch_token(authorization_response=authorization_response)
        credentials = flow.credentials
        user_info_service = build('oauth2', 'v2', credentials=credentials)
        return user_info_service.userinfo().get().execute()

    def get(self, request, **kwargs):
        if request.GET.get('state') != request.session['GOOGLE_AUTH_STATE']:
            return HttpResponseServerError("Invalid google auth state")

        user_info = self.get_user_info()
        request.session['GOOGLE_AUTH_USER_INFO'] = user_info
        return redirect(reverse_lazy("users:google-redirect"))


class GoogleRedirect(View):
    model = get_user_model()
    template_name = 'general/user-login.html'
    group = None
    role = None
    redirect_url = None

    def user_exists(self, **kwargs):
        return self.model.objects.filter(**kwargs).exists()

    def get_user(self, **kwargs):
        return get_object_or_404(self.model, **kwargs)

    def get_redirect_url(self):
        if hasattr(settings, 'LOGIN_REDIRECT_URL'):
            return reverse_lazy(settings.LOGIN_REDIRECT_URL)

        if self.redirect_url:
            return reverse_lazy(self.redirect_url)

        raise ImproperlyConfigured("LOGIN_REDIRECT_URL is not configured")

    def login_user(self, user):
        login(self.request, user)
        return redirect(self.get_redirect_url())

    def get_default_group(self):
        if hasattr(settings, "DEFAULT_USER_GROUP_NAME"):
            return get_object_or_404(Group, name=settings.DEFAULT_USER_GROUP_NAME)

        if self.group:
            return get_object_or_404(Group, name=self.group)

        raise ImproperlyConfigured("DEFAULT_USER_GROUP_NAME is not configured")

    def get_default_role(self):
        user_model = get_user_model()
        if hasattr(settings, "DEFAULT_USER_GROUP_NAME"):
            return getattr(user_model, settings.DEFAULT_USER_ROLE)

        if self.group:
            return getattr(user_model, self.role)

        raise ImproperlyConfigured("DEFAULT_USER_GROUP_NAME is not configured")

    def add_role_and_group(self, user):
        user.role = self.get_default_role()
        user.groups.add(self.get_default_group())
        user.save()
        return self.login_user(user)

    @staticmethod
    def get_names(name):
        names = name.split()
        print(name, name)
        if len(names) == 1:
            return names[0], ""
        elif len(names) == 2:
            return names[0], names[1]

    def register_user(self, user_info):
        first_name, last_name = self.get_names(user_info.get("name"))
        data = {
            "email": user_info.get("email"),
            "username": user_info.get("email"),
            "first_name": first_name,
            "last_name": last_name,
        }
        user = get_user_model().objects.create_user(**data)
        return self.add_role_and_group(user)

    def get(self, request, **kwargs):
        user_info = request.session.pop('GOOGLE_AUTH_USER_INFO')
        if self.user_exists(email=user_info.get('email')):
            user = self.get_user(email=user_info.get("email"))
            return self.login_user(user)
        else:
            return self.register_user(user_info)
