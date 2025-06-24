from django.conf.global_settings import LOGIN_REDIRECT_URL
from django.contrib.auth.tokens import default_token_generator
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from users.token.user_token import token_generator

def get_object_or_redirect(model, url=reverse_lazy(LOGIN_REDIRECT_URL), **kwargs):
    query = model.objects.filter(**kwargs)
    if query:
        return query[0]
    return redirect(url)


def get_if_exists(model, **where):
    data = model.objects.filter(**where)
    if not data:
        return None
    return data[0]


def generate_uidb64_url(pattern_name, user, absolute=False, request=None, default_generator=False, **kwargs):
    uidb64 = urlsafe_base64_encode(force_bytes(user.id))
    if default_generator:
        token = default_token_generator.make_token(user)
    else:
        token = token_generator.generate_token().make_token(user)
    url = reverse_lazy(pattern_name, kwargs={"uidb64": uidb64, "token": token, **kwargs})
    if absolute:
        return request.build_absolute_uri(url)
    return url
