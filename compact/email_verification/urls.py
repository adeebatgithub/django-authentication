from django.urls import path

from . import views

urlpatterns = [
    # email verification

    # redirect the user to the chosen method (otp/link)
    path('', views.RedirectUser.as_view(), name='verification-email-redirect'),

    # create otp
    path('create-otp/<token>/', views.VerificationOTPCreateView.as_view(), name='verification-create-otp'),
    # send an email with an otp
    path('send-mail/otp/<token>/', views.VerificationSendOTPMail.as_view(), name='verification-send-mail-otp'),
    # verify otp
    path('verify-otp/<token>/', views.VerifyAccountOTP.as_view(), name='verification-account-otp'),

    # verify email
    path(
        'update-status/<uidb64>/<token>/', views.VerificationUpdateStatus.as_view(), name='verification-update-status'
    ),
]
