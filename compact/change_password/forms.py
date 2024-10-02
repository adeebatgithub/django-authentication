from django.contrib.auth.forms import PasswordChangeForm


class ChangePasswordForm(PasswordChangeForm):
    """
    Form for changing password
    this form uses old password to verify
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["old_password"].widget.attrs["placeholder"] = "Current Password"
        self.fields["new_password1"].widget.attrs["placeholder"] = "Password"
        self.fields["new_password2"].widget.attrs["placeholder"] = "Confirm Password"
