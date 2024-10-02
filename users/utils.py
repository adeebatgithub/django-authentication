from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.conf.global_settings import LOGIN_REDIRECT_URL


def get_object_or_redirect(model, url=reverse_lazy(LOGIN_REDIRECT_URL), **kwargs):
    query = model.objects.filter(**kwargs)
    if query:
        return query[0]
    return redirect(url)