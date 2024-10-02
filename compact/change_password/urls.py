from django.urls import path

from . import views

urlpatterns = [
    # change the password and redirect the user
    path('<uidb64>/<token>/', views.PasswordChangeView.as_view(), name='change-password'),
]
