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
    path('reset-mail-sent-done/', views.MailSendDoneView.as_view(), name='mail-send-done'),
    path('create-reset-otp-mail/', views.CreateChangeOTP.as_view(), name='create-reset-otp-mail'),
    path('send-reset-otp-mail/', views.SendResetOTPMail.as_view(), name='send-reset-otp-mail'),
    path('verify-otp/', views.VerifyResetOTPView.as_view(), name='verify-password-reset-otp'),
    path('reset-password/<uidb64>/<token>/', views.PasswordResetView.as_view(), name='reset-password'),
    path('reset-password-done/', views.PasswordResetDoneView.as_view(), name='reset-password-done'),

    path('password-change/', views.PasswordChangeRedirectView.as_view(), name='password-change'),
    path('send-change-link-mail/', views.SendChangeLinkMail.as_view(), name='send-change-link-mail'),
    path('reset-mail-sent-done/', views.MailSendDoneView.as_view(), name='mail-send-done'),
    path('create-change-otp-mail/', views.CreateResetOTP.as_view(), name='create-change-otp-mail'),
    path('send-change-otp-mail/', views.SendChangeOTPMail.as_view(), name='send-change-otp-mail'),
    path('verify-otp/', views.VerifyChangeOTPView.as_view(), name='verify-password-change-otp'),
    path('change-password/<uidb64>/<token>/', views.PasswordChangeView.as_view(), name='change-password'),

    path('test/', views.test, name="test"),
]
