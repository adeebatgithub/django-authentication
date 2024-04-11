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
    path('send-reset-mail/', views.SendResetMail.as_view(), name='send-reset-mail'),
    path('reset-mail-sent-done/', views.MailSendDoneView.as_view(), name='mail-send-done'),
    path('reset-password/<pk>', views.MailSendDoneView.as_view(), name='reset-password'),

    path('test/', views.test, name="test"),
]
