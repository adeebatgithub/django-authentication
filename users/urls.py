from django.urls import path
from . import views

urlpatterns = [
    # redirect user based on authentication and autharisetion
    path('', views.RedirectUserView.as_view(), name="redirect-user"),
    # profile page
    path('profile/<username>/', views.ProfileView.as_view(), name='profile'),

    # user login
    path('login/', views.LoginView.as_view(), name='login'),
    # user lougout
    path('logout/', views.LogoutView.as_view(), name='logout'),

    # user registeration
    path('register/', views.RegisterView.as_view(), name='signup'),
    # add a role to the registered user
    path('register/add-example-role', views.AddExampleRole.as_view(), name='add-example-role'),
    # add the registered user to a grouo
    path('register/add-to-example-group/', views.AddToExampleGroup.as_view(), name='add-to-example-group'),


    # forgot password
    # two methods
    # using a url to reset password
    # path - 
    # using otp to verify and redirect to reset password

    # redirect user to give thier registered email and redirect to choosen path (otp/link)
    path('password-forgot/', views.PasswordResetRedirectView.as_view(), name='password-forgot'),

    # forgot password link method
    # send a email with password reset link
    path('send-reset-link-mail/', views.SendResetLinkMail.as_view(), name='send-reset-link-mail'),
    # redirect user to a message page
    path('reset-mail-sent-done/', views.MailSendDoneView.as_view(), name='reset-mail-send-done'),
    
    # forgot password otp method
    # send a email with a otp number
    path('send-reset-otp-mail/', views.SendResetOTPMail.as_view(), name='send-reset-otp-mail'),
    # verify otp
    path('reset-verify-otp/', views.VerifyResetOTPView.as_view(), name='verify-password-reset-otp'),

    # common for both method
    # reset the password
    path('reset-password/<uidb64>/<token>/', views.PasswordResetView.as_view(), name='reset-password'),
    # redirect the user
    path('reset-password-done/', views.PasswordResetDoneView.as_view(), name='reset-password-done'),


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
    path('verify-verification-link/<uidb64>/<token>', views.VerifyAccountLink.as_view(), name='account-verification-link'),

    # method - otp
    # send an email with an otp
    path('send-verification-otp/', views.SendVerificationOTPMail.as_view(), name='send-verification-otp'),
    # verify oto
    path('verify-verification-otp/', views.VerifyAccountOTP.as_view(), name='verify-verification-otp'),
    # verify email
    path('update-verification-status/', views.UpdateVerificationStatus.as_view(), name='update-verification-status'),

    path('test/', views.test, name="test"),
]
