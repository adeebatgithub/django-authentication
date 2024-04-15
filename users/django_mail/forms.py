from django import forms


class EmailForm(forms.Form):
    email = forms.EmailField(widget=forms.TextInput(attrs={"autocomplete": "email", "placeholder": "Enter Your Email"}))


class OTPForm(forms.Form):
    otp = forms.CharField(max_length=6, widget=forms.TextInput(attrs={"placeholder": "enter otp"}))
