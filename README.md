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
  - email varification (otp & link)
  - google oauth

*__Another better option is to use django-allauth package__*

### Instalation

clone the repo

copy the users app to your project folder

add these

setting.py

```commandline
import environ

env = environ.Env()
environ.Env.read_env()

LOGIN_URL = "users:login"

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_HOST_USER = env('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = env('EMAIL_HOST_PASSWORD')
EMAIL_USE_TLS = True

OTP_LENGTH = 6
```

crate a .env file with email informasions

urls.py

```commandline
    path('', include(('users.urls', 'users'), namespace='users'))
```
