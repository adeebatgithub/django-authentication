from django.urls import path

from . import views

verification_urlpatterns = [
    # email verification
    # methods
    # using a url to verify email
    # path -
    # using otp to verify email
    # path -

    # redirect the user to the chosen method (otp/link)
    path('verification/email/', views.RedirectUser.as_view(), name='verification-email-redirect'),

    # method link
    # send a mail with a verification link
    path('verification/email/send-mail/link/', views.VerificationSendLinkMail.as_view(), name='verification-send-mail-link'),
    # redirect user to a message page
    path('verification/email/send-mail/link/done/', views.MailSendDoneView.as_view(), name='verification-mail-send-done'),
    # verify email using link
    path('verification/email/link/<uidb64>/<token>/', views.VerifyAccountLink.as_view(),name='verification-account-link'),

    # method - otp
    # create otp
    path('verification/email/create-otp/', views.VerificationOTPCreateView.as_view(), name='verification-create-otp'),
    # send an email with an otp
    path('verification/email/send-mail/otp/', views.VerificationSendOTPMail.as_view(), name='verification-send-mail-otp'),
    # verify otp
    path('verification/email/verify-otp/', views.VerifyAccountOTP.as_view(), name='verification-account-otp'),
    # verify email
    path('verification/email/update-status/', views.VerificationUpdateStatus.as_view(), name='verification-update-status'),
]