from django.urls import path
from . import views

urlpatterns = [
    path('', views.RedirectUserView.as_view(), name="redirect-user"),
    path('profile/<username>/', views.ProfileView.as_view(), name='profile'),

    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),

    path('register/', views.RegisterView.as_view(), name='signup'),
    path('register/add-example-role', views.AddExampleRole.as_view(), name='add-example-role'),
    path('register/add-to-example-group/', views.AddToExampleGroup.as_view(), name='add-to-example-group'),

    path('password-forgot/', views.PasswordResetRedirectView.as_view(), name='password-forgot'),
    path('send-reset-link-mail/', views.SendResetLinkMail.as_view(), name='send-reset-link-mail'),
    path('reset-mail-sent-done/', views.MailSendDoneView.as_view(), name='reset-mail-send-done'),
    path('send-reset-otp-mail/', views.SendResetOTPMail.as_view(), name='send-reset-otp-mail'),
    path('reset-verify-otp/', views.VerifyResetOTPView.as_view(), name='verify-password-reset-otp'),
    path('reset-password/<uidb64>/<token>/', views.PasswordResetView.as_view(), name='reset-password'),
    path('reset-password-done/', views.PasswordResetDoneView.as_view(), name='reset-password-done'),

    path('password-change/', views.PasswordChangeRedirectView.as_view(), name='password-change'),
    path('send-change-link-mail/', views.SendChangeLinkMail.as_view(), name='send-change-link-mail'),
    path('change-mail-sent-done/', views.MailSendDoneView.as_view(), name='change-mail-send-done'),
    path('send-change-otp-mail/', views.SendChangeOTPMail.as_view(), name='send-change-otp-mail'),
    path('change-verify-otp/', views.VerifyChangeOTPView.as_view(), name='verify-password-change-otp'),
    path('change-password/<uidb64>/<token>/', views.PasswordChangeView.as_view(), name='change-password'),

    path('verify-email/', views.EmailVerificationRedirect.as_view(), name='verify-email'),
    path('send-verification-link-mail/', views.SendVerificationLinkMail.as_view(), name='send-verification-link'),
    path('send-verification-mail-done/', views.MailSendDoneView.as_view(), name='verification-mail-send-done'),
    path('verify-verification-link/<uidb64>/<token>', views.VerifyAccountLink.as_view(), name='account-verification-link'),
    path('send-verification-otp/', views.SendVerificationOTPMail.as_view(), name='send-verification-otp'),
    path('verify-verification-otp/', views.VerifyAccountOTP.as_view(), name='verify-verification-otp'),
    path('update-verification-status/', views.UpdateVerificationStatus.as_view(), name='update-verification-status'),

    path('test/', views.test, name="test"),
]
