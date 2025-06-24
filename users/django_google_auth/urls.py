from django.urls import path

from . import views

urlpatterns = [
    path('login/', views.GoogleLogin.as_view(), name='google-login'),
    path('login/callback/', views.GoogleCallback.as_view(), name='google-callback'),
    path('login/redirect/', views.GoogleRedirect.as_view(), name='google-redirect'),
]
