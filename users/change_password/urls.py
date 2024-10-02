from django.urls import path

from . import views

urlpatterns = [
    # password change
    # two methods
    #
    # path -
    # using otp to verify and redirect to change password
    # path -

    # redirect the user to confirm and direct to the chosen method(otp/link)
    path('', views.RedirectUserView.as_view(), name='change-password-redirect'),

    # method - link
    # send a mail with an url to change the password
    path('send-mail/link/<token>/', views.ChangeSendLinkMail.as_view(), name='change-send-link-mail'),
    # redirect user to a message page
    path('send-mail/done/<token>/', views.MailSendDoneView.as_view(), name='change-mail-send-done'),

    # method - otp
    # create otp model
    path('create/otp/<token>/', views.ChangeOTPCreateView.as_view(), name='change-create-otp'),
    # send a mail with an otp
    path('send-mail/otp/<token>/', views.ChangeSendOTPMail.as_view(), name='change-send-otp-mail'),
    # verify otp
    path('verify-otp/<token>/', views.ChangeVerifyOTPView.as_view(), name='change-verify-otp'),

    # common
    # change the password and redirect the user
    path('<uidb64>/<token>/', views.PasswordChangeView.as_view(), name='change-password'),
]
