from django.urls import path, include

urlpatterns = [
    path("", include("compact.general.urls")),
    path("profile/", include("compact.profile.urls")),
    path("password/forgot/", include("compact.reset_password.urls")),
    path("password/change/", include("compact.change_password.urls")),
    path("change/role/", include("compact.role_change.urls")),
    path("verification/email/", include("compact.email_verification.urls")),
    path("accounts/google/", include("compact.google_auth.urls")),
]
