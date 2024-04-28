from django.urls import path
from users import views
from users.general.urls import general_urlpatterns
from users.reset_password.urls import reset_urlpatterns

urlpatterns = [
    # password change
    # two methods
    # using a url for changing password
    # path - 
    # using otp to verify and redirect to change password
    # path - 

    # redirect the user to confirm and direct to the choosen method(otp/link) 
    path('password-change/', views.PasswordChangeRedirectView.as_view(), name='password-change'),

    # method - link
    # send a mail with a url to change the password
    path('send-change-link-mail/', views.SendChangeLinkMail.as_view(), name='send-change-link-mail'),
    # redirect user to a message page
    path('change-mail-sent-done/', views.MailSendDoneView.as_view(), name='change-mail-send-done'),

    # method - otp
    # send a mail with an otp
    path('send-change-otp-mail/', views.SendChangeOTPMail.as_view(), name='send-change-otp-mail'),
    # verify otp
    path('change-verify-otp/', views.VerifyChangeOTPView.as_view(), name='verify-password-change-otp'),

    # common
    # change the password and redirect the user
    path('change-password/<uidb64>/<token>/', views.PasswordChangeView.as_view(), name='change-password'),

    # email verification
    # methods
    # using a url to verify email
    # path - 
    # using otp to verify email
    # path - 

    # redirect the user to the choosen method (otp/link)
    path('verify-email/', views.EmailVerificationRedirect.as_view(), name='verify-email'),

    # method link
    # send a mail with a verification link
    path('send-verification-link-mail/', views.SendVerificationLinkMail.as_view(), name='send-verification-link'),
    # redirect user to a message page
    path('send-verification-mail-done/', views.MailSendDoneView.as_view(), name='verification-mail-send-done'),
    # verify email using link
    path('verify-verification-link/<uidb64>/<token>', views.VerifyAccountLink.as_view(),
         name='account-verification-link'),

    # method - otp
    # send an email with an otp
    path('send-verification-otp/', views.SendVerificationOTPMail.as_view(), name='send-verification-otp'),
    # verify oto
    path('verify-verification-otp/', views.VerifyAccountOTP.as_view(), name='verify-verification-otp'),
    # verify email
    path('update-verification-status/', views.UpdateVerificationStatus.as_view(), name='update-verification-status'),

    # change the role and grouo of an user
    # an email will pass to the settings.EMAIL_HOST_USER to verify and change role
    path('send-role-change-mail/<role>', views.SendRoleChangeMail.as_view(), name='send-role-change-mail'),
    # show success message
    path('send-role-change-mail-done/', views.RoleChangeMailSendDone.as_view(), name='send-role-change-mail-done'),
    # change role and group
    path('change-role/<uidb64>/<token>', views.RoleChangeToStaff.as_view(), name='change-role'),
    path('change-role-done-mail/', views.RoleChangeDoneMail.as_view(), name='change-role-done-mail'),
    path('change-role-fail/<uidb64>/<token>/<role>/', views.RoleChangeDecline.as_view(), name='change-role-fail'),
    path('change-role-fail-mail/', views.RoleChangeFailMail.as_view(), name='change-role-fail-mail'),
    # show success message
    path('role-change-done/', views.RoleChangeDone.as_view(), name='role-change-done'),
    path('role-change-fail/', views.RoleChangeDeclined.as_view(), name='role-change-fail'),

    path('test/', views.test, name="test"),
]

urlpatterns += general_urlpatterns + reset_urlpatterns
