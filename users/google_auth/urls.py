from django.urls import path

from . import views

google_urlpatterns = [
    path('accounts/google/login/', views.GoogleLogin.as_view(), name='google-login'),
    path('accounts/google/login/callback/', views.GoogleCallback.as_view(), name='google-callback'),
]