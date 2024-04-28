from django import forms


class EmailForm(forms.Form):
    """
    Form with email field
    """
    email = forms.EmailField(widget=forms.TextInput(attrs={"autocomplete": "email", "placeholder": "Enter Your Email"}))


class OTPForm(forms.Form):
    """
    Form with field for otp
    """
    otp = forms.CharField(max_length=6, widget=forms.TextInput(attrs={"placeholder": "enter otp"}))
