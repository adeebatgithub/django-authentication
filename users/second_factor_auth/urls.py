from django.urls import path, include

urlpatterns = [
    path("email/", include("users.second_factor_auth.email_factor.urls")),
]