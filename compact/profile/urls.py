from django.urls import path
from . import views

urlpatterns = [
    path('', views.RedirectUserView.as_view(), name='profile-redirect'),
    path('<username>/', views.ProfileView.as_view(), name='profile'),
    path('create/otp/<token>', views.OTPCreateView.as_view(), name='profile-otp-create'),
    path('send/otp/<token>', views.SendOTPMail.as_view(), name='profile-send-mail-otp'),
    path('verify/otp/<token>', views.VerifyOTP.as_view(), name='profile-otp'),
]