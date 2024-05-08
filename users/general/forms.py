from django.contrib.auth import forms as auth_forms, get_user_model


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


class ChangeUsernameForm(auth_forms.UserChangeForm):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["username"].widget.attrs["placeholder"] = "Username"

    class Meta:
        model = get_user_model()
        fields = ("username",)
        field_classes = {"username": auth_forms.UsernameField}
