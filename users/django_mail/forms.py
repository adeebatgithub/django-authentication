from django import forms


class EmailForm(forms.Form):
    """
    Form with email field
    """
    email = forms.EmailField(widget=forms.TextInput(attrs={"autocomplete": "email", "placeholder": "Enter Your Email"}))
