from django.contrib.auth import forms as auth_forms, get_user_model
from django import forms


class UserLoginForm(auth_forms.AuthenticationForm):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["username"].widget.attrs["placeholder"] = "Username"
        self.fields["password"].widget.attrs["placeholder"] = "Password"

        self.error_messages["invalid_login"] = "Invalid username or password."

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
