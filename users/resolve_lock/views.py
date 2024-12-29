from django.conf import settings
from django.contrib.auth import get_user_model, login
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse_lazy
from django.views.generic import View, RedirectView

from users.django_mail import views as mail_views
from users.models import OTPModel
from users.otp import views as otp_views
from users.token_generators.path_token import path_token_generator, PathTokenValidationMixin
from users.utils import get_object_or_redirect


class GetEmailView(mail_views.GetEmailView):
    template_name = 'users/mail/get.html'

    def get_context_data(self, **kwargs):
        context_data = super().get_context_data(**kwargs)
        context_data["title"] = "Account Verification"
        return context_data

    def get_success_url(self):
        token = path_token_generator.generate_token(session_id=self.request.session.session_key, path="email-get-lock")
        return reverse_lazy("users:lock-otp-create", kwargs={"token": token})


class OTPCreateView(PathTokenValidationMixin, View):
    pre_path = "email-get-lock"

    def get_user_model(self):
        return get_object_or_404(get_user_model(), email=self.request.session.get("USER_EMAIL"))

    def get_success_url(self):
        token = path_token_generator.generate_token(session_id=self.request.session.session_key, path="lock-otp-c")
        return reverse_lazy("users:lock-otp-send", kwargs={"token": token})

    def get(self, request, *args, **kwargs):
        user = self.get_user_model()
        otp = OTPModel(user=user, otp=otp_views.generate_otp())
        otp.save()
        request.session["OTP_ID"] = otp.id
        return redirect(self.get_success_url())


class SentOTPView(PathTokenValidationMixin, mail_views.SendEmailView):
    pre_path = "lock-otp-c"

    email_subject = "Account Activation"
    send_html_email = True
    email_template_name = "verification/user-verification-otp-mail.html"

    def get_to_email(self):
        return self.request.session.get("USER_EMAIL")

    def get_email_context_data(self):
        otp_model = get_object_or_404(OTPModel, id=self.request.session.pop("OTP_ID"))
        return {"otp": otp_model.otp}

    def get_success_url(self):
        token = path_token_generator.generate_token(session_id=self.request.session.session_key, path="lock-otp-send")
        return reverse_lazy("users:lock-otp-verify", kwargs={"token": token})


class VerifyOTP(PathTokenValidationMixin, otp_views.VerifyOTPView):
    """
    verify the otp that is provided by the user
    """
    pre_path = "lock-otp-send"
    template_name = "users/common/verify-otp.html"

    def get_user_kwargs(self):
        return {"email": self.request.session.get("USER_EMAIL")}

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update({"title": "Account Verification"})
        return context

    def get_success_url(self):
        token = path_token_generator.generate_token(session_id=self.request.session.session_key,
                                                    path="lock-otp-verified")
        return reverse_lazy("users:lock-redirection", kwargs={"token": token})


class RedirectUserView(PathTokenValidationMixin, RedirectView):
    pre_path = "lock-otp-verified"

    def get_user(self):
        return get_object_or_redirect(get_user_model(), email=self.request.session.get("USER_EMAIL"))

    def get_redirect_url(self, *args, **kwargs):
        user = self.get_user()
        login(self.request, user)
        return reverse_lazy(settings.LOGIN_REDIRECT_URL)
