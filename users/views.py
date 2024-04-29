from django.contrib.auth import get_user_model, logout
from django.contrib.auth import views as auth_views
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import ImproperlyConfigured
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse_lazy
from django.utils.http import urlsafe_base64_decode
from django.views import generic, View
from django.conf import settings

from . import forms
from .base_views import AddToGroup, AddRole, RoleChangeView
from .django_mail.mixins import SendEmailMixin
from .django_mail.views import SendEmailView, VerifyOTPView, generate_uidb64_url, generate_otp
from .models import OTPModel


def test(request):
    print(request.get_full_path())





