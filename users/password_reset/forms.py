from django.contrib.auth import forms as auth_forms


class PasswordResetForm(auth_forms.SetPasswordForm):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["new_password1"].widget.attrs["placeholder"] = "New Password"
        self.fields["new_password2"].widget.attrs["placeholder"] = "Confirm Password"
