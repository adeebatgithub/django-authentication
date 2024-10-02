from django import forms


class OTPForm(forms.Form):
    """
    Form with field for otp
    """
    otp = forms.CharField(max_length=6, widget=forms.TextInput(attrs={"placeholder": "enter otp"}))
