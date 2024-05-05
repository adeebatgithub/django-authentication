## A simple django user manager app 
- ### the app contains
  - login
  - logout
  - registration
  - give role
  - change role
  - add to group
  - change group
  - password management
    - password reset if forgotten (otp & link)
    - password change with old password (otp & link)
  - email verification (otp & link)
  - google oauth

*__Another better option is to use django-allauth package__*

### Installation

clone the repo

copy the users app to your project folder

add these

setting.py

```angular2html

INSTALLED_APPS = [
    ...

    'django.contrib.sites',

    'braces',
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'allauth.socialaccount.providers.google',

    'users.apps.UsersConfig',
]
```

```angular2html
MIDDLEWARE = [
    ...

    "allauth.account.middleware.AccountMiddleware",
]
```

```angular2html
AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
    'allauth.account.auth_backends.AuthenticationBackend',
]
```

```angular2html
LOGIN_URL = "users:login"
```

```commandline
import environ

env = environ.Env()
environ.Env.read_env()

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_HOST_USER = env('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = env('EMAIL_HOST_PASSWORD')
EMAIL_USE_TLS = True
```

```angular2html
OTP_LENGTH = 6
OTP_EXPIRY = 30
```

crate a .env file with email information

urls.py

```commandline
    path('', include(('users.urls', 'users'), namespace='users')),
    path('accounts/', include('allauth.urls')),
```
