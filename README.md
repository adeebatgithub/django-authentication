# **Django User Manager App**

A robust user management system built with Django, featuring essential functionality for user authentication, role
management, and security. This app can handle everything from basic login/logout to advanced role management and OAuth
integration.

> **Alternative**: For an even quicker setup, consider using the `django-allauth` package, which provides pre-built
> authentication flows and social login support.

---

## **Features**

- **User Authentication:**
    - Login
    - Logout
    - Registration
- **Role & Group Management:**
    - Assign roles to users
    - Modify user roles
    - Add users to groups
    - Change user groups
- **Password Management:**
    - Password reset (via OTP & link)
    - Password change with old password (via OTP & link)
- **Email Verification:**
    - Verify user emails via OTP & link
- **Google OAuth Integration**
    - Google OAuth login

---

## **Installation**

### **1. Clone the Repository**

Clone the repo and copy the `users` app to your project directory.

### **2. Configure Your Django Project**

Add the following configurations to your `settings.py`:

#### **Installed Apps**

Add `users` app to your `INSTALLED_APPS`:

```python
INSTALLED_APPS = [
    # ... other apps ...
    'users.apps.UsersConfig',  # Your users app
]
```

#### **Login URLs**

Set the login and redirect URLs:

```python
LOGIN_URL = "users:login"  # URL to the login page
LOGIN_REDIRECT_URL = "users:redirect-user"  # URL to redirect post-login
```

#### **Default Role & Group**

Set default role and group for new users:

```python
DEFAULT_USER_ROLE = '<ROLE_NAME>'  # Assign a default role to new users
DEFAULT_USER_GROUP_NAME = '<GROUP_NAME>'  # Add new users to this default group
```

#### **Email Configuration**

Configure the email backend for sending OTPs, verification emails, etc. using Gmail:

```python
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_HOST_USER = '<EMAIL_ID>'  # Your Gmail ID
EMAIL_HOST_PASSWORD = '<APP_PASSWORD>'  # Google app password (use an app-specific password)
EMAIL_USE_TLS = True
```

#### **Token Expiry**

Set the expiration time for tokens (such as password reset tokens):

```python
# Token expiry configuration in minutes, hours, etc.
TOKEN_EXPIRY = {
    "minutes": 10  # Default is 10 minutes
}
```

#### **OTP Configuration**

Configure the length and expiry of OTPs:

```python
OTP_LENGTH = 6  # Preferred length of OTP (4 or 6 digits)
OTP_EXPIRY = {
    "seconds": 10,  # Expiry duration
    "minutes": 30
}
```

#### **Google OAuth Setup**

Configure Google OAuth using credentials from the Google API Console:

```python
if DEBUG:
    # Use in development only (not recommended for production)
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

GOOGLE_AUTH = {
    'client_id': '<GOOGLE_CLIENT_ID>',  # Client ID from Google API
    'client_secret_file': '<GOOGLE_SECRET_FILE>',  # JSON file from Google API
    'redirect_uri': '<REDIRECT_URI>',  # Redirect URI registered with Google API
    'scopes': ['<SCOPE_URL>'],  # Google scope URLs for required permissions
    'access_type': '<ACCESS_TYPE>',  # Access type, e.g
}
```

---

### **3. URLs Configuration**

Update your project’s `urls.py` to include the `users` app URLs:

```python
path('', include(('users.urls', 'users'), namespace='users')),
```

---

## **Conclusion**

Your Django user manager app is now ready! This app provides a comprehensive user management system out of the box, with
support for role management, password handling, and even Google OAuth. Customize the settings as per your project
requirements.

For more advanced use cases or faster integration of social login, you can always explore using the `django-allauth`
package.

---

