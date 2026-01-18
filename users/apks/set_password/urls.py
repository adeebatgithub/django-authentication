from django.urls import path

from .views import SetPasswordView

urlpatterns = [
    path('', SetPasswordView.as_view(), name='set-password'),
]