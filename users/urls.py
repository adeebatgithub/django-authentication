from django.urls import path, include

urlpatterns = [
    path("", include("users.general.urls")),
    path("password/forgot/", include("users.reset_password.urls")),
    path("password/change/", include("users.change_password.urls")),
    path("change/role/", include("users.role_change.urls")),
    path("verification/email/", include("users.email_verification.urls")),
    path("accounts/google/", include("users.google_auth.urls")),
]
