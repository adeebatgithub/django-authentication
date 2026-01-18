from django import forms
from django.conf import settings
from django.contrib.auth import forms as auth_forms, get_user_model
from django.core.exceptions import ValidationError

import users.models
from users.utils import get_if_exists


class UserLoginForm(auth_forms.AuthenticationForm):
    class Meta:
        model = get_user_model()
        fields = ['username', 'password']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["username"].widget.attrs["placeholder"] = "Username or Email"
        self.fields["password"].widget.attrs["placeholder"] = "Password"

    def clean(self):
        clean_data = self.cleaned_data
        username = clean_data.get("username")

        if "@" in username:
            where = {"email": username}
        else:
            where = {"username": username}
        user = get_if_exists(get_user_model(), **where)

        if user:
            if user.is_locked():
                self.error_messages["account_locked"] = f"Your Account is locked {user.get_lock_status_display()}"
                raise ValidationError(
                    f"Your Account is locked {user.get_lock_status_display()}",
                    code="account_locked"
                )
            if not user.is_superuser and settings.LOCK_USER:
                user.increment_login_attempts()

        try:
            return super().clean()
        except ValidationError as e:
            if user and 'invalid_login' in str(e.code):
                login_attempts = getattr(user, 'login_attempts', 0)
                error_message = f"Invalid username or password. Login attempts Left: {settings.MIN_LOGIN_ATTEMPT_LIMIT - login_attempts}"
                raise ValidationError(error_message, code='invalid_login')
            raise

    def reset_login_attempts(self):
        username = self.cleaned_data.get("username")
        if username:
            user = get_if_exists(get_user_model(), username=username)
            if user:
                user.reset_login_attempts()


class UserRegistrationForm(auth_forms.UserCreationForm):
    class Meta:
        model = get_user_model()
        fields = ("username", "email", "password1", "password2")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["username"].widget.attrs["placeholder"] = "Username"
        self.fields["email"].widget.attrs["placeholder"] = "Email"
        self.fields["password1"].widget.attrs["placeholder"] = "Password"
        self.fields["password2"].widget.attrs["placeholder"] = "Confirm Password"

    def clean(self):
        clean_data = self.cleaned_data
        email = clean_data.get("email")
        user = get_if_exists(get_user_model(), email=email)
        if user:
            raise ValidationError("Email already exists")
        return clean_data


class ChangeUsernameForm(forms.ModelForm):
    class Meta:
        model = get_user_model()
        fields = ("username",)
        field_classes = {"username": auth_forms.UsernameField}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["username"].widget.attrs["placeholder"] = "Username"


class ChangeFullnameForm(forms.ModelForm):
    class Meta:
        model = get_user_model()
        fields = ("first_name", "last_name")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["first_name"].widget.attrs["placeholder"] = "First Name"
        self.fields["last_name"].widget.attrs["placeholder"] = "Last Name"


class ChangeEmailForm(forms.ModelForm):
    class Meta:
        model = get_user_model()
        fields = ("email",)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["email"].widget.attrs["placeholder"] = "Email"
