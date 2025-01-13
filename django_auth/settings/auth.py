from . import env

LOGIN_URL = "users:login"
LOGIN_REDIRECT_URL = "users:redirect-user"
SECOND_FACTOR_VERIFICATION_URL = "users:email-factor"
AUTO_LOGOUT_DELAY = 1209600
LOGIN_ATTEMPT_LIMIT = 5

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_HOST_USER = env('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = env('EMAIL_HOST_PASSWORD')
EMAIL_USE_TLS = True

TOKEN_EXPIRY = {
    # "seconds": 10,
    "minutes": 10
}
OTP_LENGTH = 6
OTP_EXPIRY = {
    "minutes": 30,
}

DEFAULT_USER_ROLE = 'EXAMPLE_ROLE'
DEFAULT_USER_GROUP_NAME = 'example'

GOOGLE_AUTH = {
    'client_id': env('GOOGLE_CLIENT_ID'),
    'client_secret_file': 'django_auth/client_secret.json',
    'redirect_uri': f'http://127.0.0.1:8000/accounts/google/login/callback/',
    "scopes": [
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
    ],
    "access_type": 'offline',
}
