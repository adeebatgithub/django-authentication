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

    'users.apps.UsersConfig',
]
```

```angular2html
LOGIN_URL = "users:login"
LOGIN_REDIRECT_URL = "users:redirect-user"
```

```angular2html
DEFAULT_USER_ROLE = '<ROLE_NAME>' # a defualt role to give a new user
DEFAULT_USER_GROUP_NAME = '<GROUP_NAME>' # a default group to add new users to
```

```commandline
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_HOST_USER = '<EMAIL_ID>' # gmail id for sending emails
EMAIL_HOST_PASSWORD = '<APP_PASSWORD>' # app password provided by the google
EMAIL_USE_TLS = True
```

```angular2html
OTP_LENGTH = 6
OTP_EXPIRY = 30
```

```angular2html
if DEBUG:
    # only use in the development
    # not a good practice to use in production
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

GOOGLE_AUTH = {
    'client_id': '<GOOGLE_CLIENT_ID>', # client id provided by google api
    'client_secret_file': '<GOOGLE_SECRETE_FILE>', # json file provided py google api
    'redirect_uri': '<REDIRECT_URI>', # redirect uri provided when creating google api
    "scopes": ['<SCOPE_URL>'], # google scope urls that are needed
    "access_type": '<ACCESS_TYPE>', # access type offline or online
}
```

crate a .env file with email information

urls.py

```commandline
    path('', include(('users.urls', 'users'), namespace='users')),
```
