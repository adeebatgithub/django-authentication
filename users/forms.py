from django.contrib.auth import get_user_model
from django.contrib.auth import forms as auth_forms
from django import forms


class UserLoginForm(auth_forms.AuthenticationForm):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["username"].widget.attrs["placeholder"] = "Username"
        self.fields["password"].widget.attrs["placeholder"] = "Password"

    class Meta:
        model = get_user_model()
        fields = ['username', 'password']


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


class ChangePasswordForm(auth_forms.PasswordChangeForm):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["old_password"].widget.attrs["placeholder"] = "Current Password"
        self.fields["new_password1"].widget.attrs["placeholder"] = "Password"
        self.fields["new_password2"].widget.attrs["placeholder"] = "Confirm Password"


class PasswordResetForm(auth_forms.SetPasswordForm):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["new_password1"].widget.attrs["placeholder"] = "New Password"
        self.fields["new_password2"].widget.attrs["placeholder"] = "Confirm Password"
