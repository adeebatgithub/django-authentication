from django.urls import path

from . import views

urlpatterns = [
    path("send/otp/<token>/", views.SentOTPView.as_view(), name="email-factor"),
    path("verify/<token>", views.VerifyOTP.as_view(), name="email-factor-verify"),
]
