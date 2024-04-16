import random

from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import ImproperlyConfigured
from django.shortcuts import redirect, get_object_or_404
from django.urls import reverse_lazy
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.views import generic, View
from django.views.generic import TemplateView

from .forms import EmailForm, OTPForm
from .mixins import SendEmailMixin, FormMixin


class SendEmailView(FormMixin, SendEmailMixin, TemplateView):
    template_name = None
    success_url = None
    form_class = EmailForm
    email_field_name = "email"

    def get_email_context_data(self):
        pass

    def form_valid(self, form):
        User = get_user_model()
        email = form.cleaned_data[self.email_field_name]
        if User.objects.filter(email=email).exists():
            self.request.session["email"] = email
            self.send_mail()
            return redirect(self.get_success_url())
        form.add_error("email", "This email is not registered")
        return self.render_to_response(self.get_context_data(form=form))


def generate_reset_url(pattern_name, user, absolute=False, request=None):
    uidb64 = urlsafe_base64_encode(force_bytes(user.id))
    token = default_token_generator.make_token(user)
    url = reverse_lazy(pattern_name, kwargs={"uidb64": uidb64, "token": token})
    if absolute:
        return request.build_absolute_uri(url)
    return url


def generate_otp():
    return random.randint(100000, 999999)


class VerifyOTPView(FormMixin, generic.TemplateView):
    """
    verify the OTP
    """
    template_name = None
    model = None
    success_url = None
    form_class = OTPForm
    user_kwargs = {}

    def get_user_kwargs(self):
        return self.user_kwargs

    def get_user_model(self):
        return get_object_or_404(get_user_model(), **self.get_user_kwargs())

    def get_otp_model(self):
        user = self.get_user_model()
        return get_object_or_404(self.get_model(), user=user)

    def get_model(self):
        if self.model is None:
            raise ImproperlyConfigured(f"{self.__class__.__name__} has no model specified")
        return self.model

    def form_valid(self, form):
        if self.get_model().objects.filter(user=self.get_user_model()):
            otp_model = self.get_otp_model()
            otp_number = form.cleaned_data.get("otp")
            if otp_number == otp_model.otp:
                otp_model.delete()
                if otp_model.is_expired():
                    form.add_error("otp", "OTP is expired")
                    return self.render_to_response(self.get_context_data(form=form))
                return redirect(self.get_success_url())
        form.add_error("otp", "OTP is not valid")
        return self.render_to_response(self.get_context_data(form=form))
