from braces.views import LoginRequiredMixin
from django.conf import settings
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.views.generic import RedirectView

from users.utilities.mailing import views as mail_views
from users.utilities.otp import views as otp_views
from users.models import OTPModel
from users.utilities.token.user_token import token_generator, PathTokenValidationMixin


class ResentOTPView(LoginRequiredMixin, RedirectView):

    def get_redirect_url(self):
        token = token_generator.generate_token(path="second-factor-verification").make_token(self.request.user)
        return redirect(reverse_lazy(settings.SECOND_FACTOR_VERIFICATION_URL, kwargs={"token": token}))


class SentOTPView(LoginRequiredMixin, PathTokenValidationMixin, mail_views.SendEmailView):
    pre_path = "second-factor-verification"

    email_subject = "2FA Authentication"
    send_html_email = True
    email_template_name = "users/second_factor_auth/email_factor/otp.html"

    def get_to_email(self):
        return self.request.user.email

    def get_email_context_data(self):
        otp_model = OTPModel.objects.create(
            user=self.request.user,
            otp=otp_views.generate_otp(),
        )
        return {
            "otp": otp_model.otp,
            "user": self.request.user.username,
        }

    def get_success_url(self):
        token = token_generator.generate_token(path="email-factor-send").make_token(self.request.user)
        return reverse_lazy("users:email-factor-verify", kwargs={"token": token})


class VerifyOTP(LoginRequiredMixin, PathTokenValidationMixin, otp_views.VerifyOTPView):
    """
    verify the otp that is provided by the user
    """
    pre_path = "email-factor-send"
    template_name = "users/second_factor_auth/email_factor/verify-otp.html"

    def get_user_model(self):
        return self.request.user

    def verify_second_factor(self):
        self.request.user.verify_second_factor()
        self.request.session["2FA_STATUS"] = True
        return reverse_lazy(settings.LOGIN_REDIRECT_URL)

    def get_success_url(self):
        return self.verify_second_factor()
