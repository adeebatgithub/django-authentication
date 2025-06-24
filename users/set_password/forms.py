from django.contrib.auth.forms import SetPasswordForm


class PasswordSetForm(SetPasswordForm):

    def __init__(self, *args, **kwargs):
        super(PasswordSetForm, self).__init__(*args, **kwargs)
        self.fields['new_password1'].widget.attrs.update({'autofocus': 'on', 'placeholder': 'New Password'})
        self.fields['new_password2'].widget.attrs.update({'placeholder': 'Confirm New Password'})

    def save(self, commit=True):
        print(self.cleaned_data["new_password1"])
        return super(PasswordSetForm, self).save(commit=commit)