import random

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.shortcuts import redirect, get_object_or_404
from django.views import generic, View

from users.models import OTPModel
from .forms import OTPForm
from users.mixins import FormMixin


def generate_otp():
    min_ = "1" + ("0" * (settings.OTP_LENGTH - 1))
    max_ = "9" * settings.OTP_LENGTH
    return random.randint(min_, max_)


class OTPCreateView(View):
    success_url = None
    user = None

    def get_user_model(self):
        return self.user

    def get_success_url(self):
        return self.success_url

    def get(self, request, *args, **kwargs):
        user = self.get_user_model()
        otp = OTPModel(user=user, otp=generate_otp())
        otp.save()
        request.session["OTP_ID"] = otp.id
        return redirect(self.get_success_url())


class VerifyOTPView(FormMixin, generic.TemplateView):
    """
    verify the OTP
    """
    template_name = None
    model = OTPModel
    success_url = None
    form_class = OTPForm
    user_kwargs = {}

    def get_user_kwargs(self):
        return self.user_kwargs

    def get_user_model(self):
        return get_object_or_404(get_user_model(), **self.get_user_kwargs())

    def get_otp_model(self, otp_number):
        return get_object_or_404(self.get_model(), otp=otp_number)

    def get_model(self):
        if self.model is None:
            raise ImproperlyConfigured(f"{self.__class__.__name__} has no model specified")
        return self.model

    def form_valid(self, form):
        if self.get_model().objects.filter(user=self.get_user_model()):
            otp_number = form.cleaned_data.get("otp")
            otp_model = self.get_otp_model(otp_number)
            if otp_model.user.id == self.get_user_model().id:
                if otp_number == otp_model.otp:
                    otp_model.delete()
                    if otp_model.is_expired():
                        form.add_error("otp", "OTP is expired")
                        return self.render_to_response(self.get_context_data(form=form))
                    return redirect(self.get_success_url())
        form.add_error("otp", "OTP is not valid")
        return self.render_to_response(self.get_context_data(form=form))
