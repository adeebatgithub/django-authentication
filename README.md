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

```python
INSTALLED_APPS = [
    ...

    'users.apps.UsersConfig',
]
```

```python
LOGIN_URL = "users:login"
LOGIN_REDIRECT_URL = "users:redirect-user"
```

```python
DEFAULT_USER_ROLE = '<ROLE_NAME>' # a defualt role to give a new user
DEFAULT_USER_GROUP_NAME = '<GROUP_NAME>' # a default group to add new users to
```

```python
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_HOST_USER = '<EMAIL_ID>' # gmail id for sending emails
EMAIL_HOST_PASSWORD = '<APP_PASSWORD>' # app password provided by the google
EMAIL_USE_TLS = True
```

```python
# expiring time of tokens used in this app
# dict of times im sec or min or hrs or combined
# optional default to 10 min
TOKEN_EXPIRY = {
    "minutes": 10
}
```

```python
OTP_LENGTH = 6 # length of the otp 4 or 6 is preferred

# dict of times im sec or min or hrs or combined
# optional default to 30 min
OTP_EXPIRY = {
    "seconds": 10,
    "minutes": 30
}
```

```python
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

urls.py

```python
    path('', include(('users.urls', 'users'), namespace='users')),
```
