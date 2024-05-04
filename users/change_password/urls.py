from django.urls import path

from . import views

change_urlpatterns = [
    # password change
    # two methods
    #
    # path -
    # using otp to verify and redirect to change password
    # path -

    # redirect the user to confirm and direct to the chosen method(otp/link)
    path('password/change/', views.RedirectUserView.as_view(), name='change-password-redirect'),

    # method - link
    # send a mail with an url to change the password
    path('password/change/send-mail/link/', views.ChangeSendLinkMail.as_view(), name='change-send-link-mail'),
    # redirect user to a message page
    path('password/change/send-mail/done/', views.MailSendDoneView.as_view(), name='change-mail-send-done'),

    # method - otp
    # create otp model
    path('password/change/create/otp/', views.ChangeOTPCreateView.as_view(), name='change-create-otp'),
    # send a mail with an otp
    path('password/change/send-mail/otp/', views.ChangeSendOTPMail.as_view(), name='change-send-otp-mail'),
    # verify otp
    path('password/change/verify-otp/', views.ChangeVerifyOTPView.as_view(), name='change-verify-otp'),

    # common
    # change the password and redirect the user
    path('password/change/<uidb64>/<token>/', views.PasswordChangeView.as_view(), name='change-password'),
]
