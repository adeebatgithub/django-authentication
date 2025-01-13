from django.urls import path, include

urlpatterns = [
    path("email/", include("users.auth_factor.email_factor.urls")),
]