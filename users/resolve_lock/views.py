from django.conf import settings
from django.contrib.auth import get_user_model, login
from django.shortcuts import get_object_or_404
from django.urls import reverse_lazy
from django.views import generic
from django.views.generic import RedirectView

from users.django_mail import views as mail_views
from users.django_otp import views as otp_views
from users.models import OTPModel
from users.token.path_token import path_token_generator, PathTokenValidationMixin
from users.utils import get_object_or_redirect


class GetEmailView(mail_views.GetEmailView):
    template_name = 'users/resolve-lock/get-mail.html'

    def get_success_url(self):
        token = path_token_generator.generate_token(session_id=self.request.session.session_key, path="email-get-lock")
        return reverse_lazy("users:lock-otp-send", kwargs={"token": token})


class ResentOTPView(generic.RedirectView):

    def get_redirect_url(self):
        token = path_token_generator.generate_token(session_id=self.request.session.session_key, path="email-get-lock")
        return reverse_lazy("users:lock-otp-send", kwargs={"token": token})


class SentOTPView(PathTokenValidationMixin, mail_views.SendEmailView):
    pre_path = "email-get-lock"

    email_subject = "Account Activation"
    send_html_email = True
    email_template_name = "users/resolve-lock/otp.html"

    def get_to_email(self):
        return self.request.session.get("USER_EMAIL")

    def get_email_context_data(self):
        user = get_object_or_404(get_user_model(), email=self.get_to_email())
        otp_model = OTPModel.objects.create(
            user=user,
            otp=otp_views.generate_otp(),
        )
        return {
            "otp": otp_model.otp,
            "user": user.username
        }

    def get_success_url(self):
        token = path_token_generator.generate_token(session_id=self.request.session.session_key, path="lock-otp-send")
        return reverse_lazy("users:lock-otp-verify", kwargs={"token": token})


class VerifyOTP(PathTokenValidationMixin, otp_views.VerifyOTPView):
    """
    verify the otp that is provided by the user
    """
    pre_path = "lock-otp-send"
    template_name = "users/resolve-lock/verify-otp.html"

    def get_user_kwargs(self):
        return {"email": self.request.session.get("USER_EMAIL")}

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
