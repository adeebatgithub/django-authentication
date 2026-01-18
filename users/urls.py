from django.urls import path, include

app_name = 'users'

urlpatterns = [
    path("", include("users.apks.general.urls")),
    path("profile/", include("users.apks.profile.urls")),
    path("password/forgot/", include("users.apks.password_reset.urls")),
    path("password/change/", include("users.apks.password_change.urls")),
    path("verification/email/", include("users.apks.email_verification.urls")),
    path("accounts/google/", include("users.oauth.google.urls")),
    path("password/set/", include("users.apks.set_password.urls")),
    path("resolve/account/lock/", include("users.apks.resolve_lock.urls")),
    path("2FA/", include("users.apks.second_factor_auth.urls")),
    path("deletion/", include("users.apks.user_deletion.urls")),
]
