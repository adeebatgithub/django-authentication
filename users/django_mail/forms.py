from django import forms
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

from users.utils import get_if_exists


class EmailForm(forms.Form):
    """
    Form with email field
    """
    email = forms.EmailField(widget=forms.TextInput(attrs={"autocomplete": "email", "placeholder": "Enter Your Email"}))

    def clean(self):
        clean_data = self.cleaned_data
        user = get_if_exists(get_user_model(), email=clean_data.get("email"))
        if not user:
            raise ValidationError("No Account Found")
        return super().clean()
