from django.contrib.auth import forms as auth_forms


class ChangePasswordForm(auth_forms.PasswordChangeForm):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["old_password"].widget.attrs["placeholder"] = "Current Password"
        self.fields["new_password1"].widget.attrs["placeholder"] = "Password"
        self.fields["new_password2"].widget.attrs["placeholder"] = "Confirm Password"
