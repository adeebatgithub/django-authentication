from django.urls import path, include
from .validator_api import UserNameValidator, EmailValidator

urlpatterns = [
    path("", include("users.general.urls")),
    path("password/forgot/", include("users.reset_password.urls")),
    path("password/change/", include("users.change_password.urls")),
    path("change/role/", include("users.role_change.urls")),
    path("verification/email/", include("users.email_verification.urls")),
    path("accounts/google/", include("users.google_auth.urls")),

    # validators
    path("validate/username/<str:username>/", UserNameValidator.as_view()),
    path("validate/email/<str:email>/", EmailValidator.as_view())
]
