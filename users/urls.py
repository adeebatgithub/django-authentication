from django.urls import path, include
from .validator_api import UserNameValidator, EmailValidator

urlpatterns = [
    path("", include("users.general.urls")),
    path("password/forgot/", include("users.password_reset.urls")),
    path("password/change/", include("users.password_change.urls")),
    path("change/role/", include("users.role_change.urls")),
    path("verification/email/", include("users.email_verification.urls")),
    path("accounts/google/", include("users.django_google_auth.urls")),
    path("password/set/", include("users.set_password.urls")),
    path("resolve/account/lock/", include("users.resolve_lock.urls")),
    path("2FA/", include("users.second_factor_auth.urls")),
    path("deletion/", include("users.user_deletion.urls")),

    # validators
    path("validate/username/<str:username>/", UserNameValidator.as_view()),
    path("validate/email/<str:email>/", EmailValidator.as_view())
]
