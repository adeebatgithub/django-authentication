from django import forms
from django.contrib.auth import forms as auth_forms, get_user_model
from django.core.exceptions import ValidationError

import users.models
from users.utils import get_if_exists


class UserLoginForm(auth_forms.AuthenticationForm):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["username"].widget.attrs["placeholder"] = "Username or Email"
        self.fields["password"].widget.attrs["placeholder"] = "Password"

        self.error_messages["invalid_login"] = "Invalid username or password."

    class Meta:
        model = get_user_model()
        fields = ['username', 'password']

    def clean(self):
        clean_data = self.cleaned_data
        username = clean_data.get("username")
        if "@" in username:
            where = {"email": username}
        else:
            where = {"username": username}
        user: users.models.User = get_if_exists(get_user_model(), **where)
        print(user.login_attempts)
        if user:
            if user.is_locked:
                self.error_messages["account_locked"] = f"Your Account is locked {user.get_lock_status_display()}"
                raise ValidationError(
                    f"Your Account is locked {user.get_lock_status_display()}",
                    code="account_locked"
                )
            if not user.is_superuser:
                user.increment_login_attempts()
        return super().clean()

    def reset_login_attempts(self):
        username = self.cleaned_data.get("username")
        if username:
            user = get_if_exists(get_user_model(), username=username)
            if user:
                user.reset_login_attempts()


class UserRegistrationForm(auth_forms.UserCreationForm):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["username"].widget.attrs["placeholder"] = "Username"
        self.fields["email"].widget.attrs["placeholder"] = "Email"
        self.fields["password1"].widget.attrs["placeholder"] = "Password"
        self.fields["password2"].widget.attrs["placeholder"] = "Confirm Password"

    class Meta:
        model = get_user_model()
        fields = ("username", "email", "password1", "password2")


class ChangeUsernameForm(forms.ModelForm):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["username"].widget.attrs["placeholder"] = "Username"

    class Meta:
        model = get_user_model()
        fields = ("username",)
        field_classes = {"username": auth_forms.UsernameField}


class ChangeFullnameForm(forms.ModelForm):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["first_name"].widget.attrs["placeholder"] = "First Name"
        self.fields["last_name"].widget.attrs["placeholder"] = "Last Name"

    class Meta:
        model = get_user_model()
        fields = ("first_name", "last_name")


class ChangeEmailForm(forms.ModelForm):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["email"].widget.attrs["placeholder"] = "Email"

    class Meta:
        model = get_user_model()
        fields = ("email",)
