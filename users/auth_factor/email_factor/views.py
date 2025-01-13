from braces.views import LoginRequiredMixin
from django.conf import settings
from django.shortcuts import get_object_or_404
from django.urls import reverse_lazy

from users.django_mail import views as mail_views
from users.models import OTPModel
from users.otp import views as otp_views
from users.token_generators.user_token import PathTokenValidationMixin, token_generator


class SentOTPView(LoginRequiredMixin, PathTokenValidationMixin, mail_views.SendEmailView):
    pre_path = "second-factor-verification"

    email_subject = "2FA Authentication"
    send_html_email = True
    email_template_name = "users/mail/otp.html"

    def get_to_email(self):
        return self.request.user.email

    def get_email_context_data(self):
        otp_model, _ = OTPModel.objects.get_or_create(
            user=self.request.user,
            defaults={
                "user": self.request.user,
                "otp": otp_views.generate_otp(),
            }
        )
        return {
            "otp": otp_model.otp,
            "subject": self.email_subject,
            "content": "OTP for 2FA authentication",
        }

    def get_success_url(self):
        token = token_generator.generate_token(path="email-factor-send").make_token(self.request.user)
        return reverse_lazy("users:email-factor-verify", kwargs={"token": token})


class VerifyOTP(LoginRequiredMixin, PathTokenValidationMixin, otp_views.VerifyOTPView):
    """
    verify the otp that is provided by the user
    """
    pre_path = "email-factor-send"
    template_name = "users/common/verify-otp.html"

    def get_user_model(self):
        return self.request.user

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update({"title": "Account Verification"})
        return context

    def get_success_url(self):
        self.request.user.verify_second_factor()
        return reverse_lazy(settings.LOGIN_REDIRECT_URL)
