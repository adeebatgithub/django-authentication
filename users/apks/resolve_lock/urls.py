from django.urls import path

from . import views

urlpatterns = [
    path("", views.GetEmailView.as_view(), name="get-email-lock"),
    path("send/otp/<token>/", views.SentOTPView.as_view(), name="lock-otp-send"),
    path("resend/otp/", views.ResentOTPView.as_view(), name="lock-otp-resend"),
    path("verify/otp/<token>/", views.VerifyOTP.as_view(), name="lock-otp-verify"),
    path("redirection/<token>/", views.RedirectUserView.as_view(), name="lock-redirection"),
]
