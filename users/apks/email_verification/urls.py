from django.urls import path

from . import views

urlpatterns = [
    # email verification
    # methods
    # using an url to verify email
    # path -
    # using otp to verify email
    # path -

    # redirect the user to the chosen method (otp/link)
    path('', views.RedirectUser.as_view(), name='verification-email-redirect'),

    # method link
    # send a mail with a verification link
    path('send-mail/link/<token>/', views.VerificationSendLinkMail.as_view(), name='verification-send-mail-link'),
    # redirect user to a message page
    path('send-mail/link/done/<token>/', views.MailSendDoneView.as_view(), name='verification-mail-send-done'),

    # method - otp
    # send an email with an otp
    path('send-mail/otp/<token>/', views.VerificationSendOTPMail.as_view(), name='verification-send-mail-otp'),
    # verify otp
    path('verify-otp/<token>/', views.VerifyAccountOTP.as_view(), name='verification-account-otp'),
    # resend otp
    path('resend-otp/', views.VerificationResendOTPMail.as_view(), name='verification-resend-mail-otp'),

    # verify email
    path(
        'update-status/<uidb64>/<token>/', views.VerificationUpdateStatus.as_view(), name='verification-update-status'
    ),
]
