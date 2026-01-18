from django.urls import path, include

urlpatterns = [
    path("email/", include("users.apks.second_factor_auth.email_factor.urls")),
]