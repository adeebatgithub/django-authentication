from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.core import signing

from users.models import TokenModel


class TokenGenerator:
    model = TokenModel

    def __init__(self):
        self.token = None

    def generate_token(self, **kwargs):
        self.token = signing.dumps(kwargs)
        return self

    def create_token_model(self, user, token):
        model = self.model.objects.create(user=user, token=token)
        return model

    def get_token_model(self, token):
        return self.model.objects.filter(token=token).last()

    def make_token(self, user):
        self.create_token_model(user, self.token)
        return self.token

    def delete_token(self, token=None, model=None):
        if model:
            model.delete()

        if token:
            model = self.get_token_model(token)
            model.delete()

    def is_valid(self, user, token):
        model = self.get_token_model(token)
        if not model:
            return False

        if model.user != user:
            self.delete_token(model=model)
            return False

        if model.is_expired():
            self.delete_token(model=model)
            return False

        return True


token_generator = TokenGenerator()


class TokenValidationMixin:
    token_url_kwarg = 'token'
    token_invalid_redirect_url = reverse_lazy("users:redirect-user")

    def token_invalid(self):
        # message
        return redirect(self.token_invalid_redirect_url)

    def get_user(self):
        return self.request.user

    def dispatch(self, request, *args, **kwargs):
        if token_generator.is_valid(self.get_user(), kwargs.get(self.token_url_kwarg)):
            return super().dispatch(request, *args, **kwargs)
        return self.token_invalid()


class PathTokenValidationMixin(TokenValidationMixin):
    pre_path = None

    def dispatch(self, request, *args, **kwargs):
        if request.method == "GET":
            params = signing.loads(self.kwargs.get("token"))
            if params.get("path") != self.pre_path:
                return self.token_invalid()

        return super().dispatch(request, *args, **kwargs)
