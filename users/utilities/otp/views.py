import random

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.shortcuts import redirect, get_object_or_404
from django.views import generic, View
from django.views.generic import FormView

from users.models import OTPModel
from .forms import OTPForm


def generate_otp():
    min_ = "1" + ("0" * (settings.OTP_LENGTH - 1))
    max_ = "9" * settings.OTP_LENGTH
    return random.randint(int(min_), int(max_))


class OTPCreateView(View):
    success_url = None
    user_kwargs = {}

    def get_user_kwargs(self):
        if not hasattr(self, 'user_kwargs'):
            raise ImproperlyConfigured(
                f"{self.__class__.__name__} unable to get user specify 'user_kwargs' or 'get_user_model'")
        return self.user_kwargs

    def get_user_model(self):
        return get_object_or_404(get_user_model(), **self.get_user_kwargs())

    def get_success_url(self):
        if not hasattr(self, 'success_url'):
            raise ImproperlyConfigured(f"{self.__class__.__name__} redirect url not found")
        return self.success_url

    def get(self, request, *args, **kwargs):
        user = self.get_user_model()
        otp = OTPModel.objects.create(user=user, otp=generate_otp())
        request.session["OTP_ID"] = otp.id
        return redirect(self.get_success_url())


class VerifyOTPView(FormView, generic.TemplateView):
    """
    verify the OTP
    """
    model = OTPModel
    form_class = OTPForm
    user_kwargs = {}

    def get_user_kwargs(self):
        if not hasattr(self, 'user_kwargs'):
            raise ImproperlyConfigured(
                f"{self.__class__.__name__} unable to get user specify 'user_kwargs' or 'get_user_model'")
        return self.user_kwargs

    def get_user_model(self):
        return get_object_or_404(get_user_model(), **self.get_user_kwargs())

    def get_otp_model(self, otp_number):
        return get_object_or_404(self.get_model(), otp=otp_number)

    def get_model(self):
        if self.model is None:
            raise ImproperlyConfigured(f"{self.__class__.__name__} has no model specified")
        return self.model

    def otp_invalid(self, form):
        form.add_error("otp", "OTP is not valid")
        return self.render_to_response(self.get_context_data(form=form))

    def is_valid(self, otp_model, otp_number):
        if not self.get_model().objects.filter(user=self.get_user_model()):
            return False

        if otp_model.user.id != self.get_user_model().id:
            return False

        if otp_number != otp_model.otp:
            return False

        if otp_model.is_expired():
            return False

    def form_valid(self, form):
        otp_number = form.cleaned_data.get("otp")
        otp_model = self.get_otp_model(otp_number)
        if self.is_valid(otp_model, otp_number):
            return self.otp_invalid(form)

        otp_model.delete()
        return redirect(self.get_success_url())
