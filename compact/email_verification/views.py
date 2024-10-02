from braces.views import LoginRequiredMixin
from django.contrib.auth import get_user_model
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.views import generic, View

from compact.django_mail import views as mail_views
from compact.models import OTPModel
from compact.otp import views as otp_views
from compact.token import PathTokenValidationMixin, token_generator
from compact.utils import get_object_or_redirect, generate_uidb64_url


class RedirectUser(LoginRequiredMixin, generic.RedirectView):
    """
    redirect the user to confirm send email
    otp = True will send an otp instead of link
    """
    otp_pattern_name = "compact:verification-create-otp"

    def get_redirect_url(self):
        if self.request.user.email_verified:
            return reverse_lazy("compact:profile", kwargs={"username": self.request.user.username})

        token = token_generator.generate_token(user_id=self.request.user.id, path="email-redirect").make_token(
            self.request.user)
        return reverse_lazy(self.otp_pattern_name, kwargs={"token": token})


class VerificationOTPCreateView(LoginRequiredMixin, PathTokenValidationMixin, otp_views.OTPCreateView):
    pre_path = "email-redirect"

    def get_user_model(self):
        return self.request.user

    def get_success_url(self):
        token = token_generator.generate_token(user_id=self.request.user.id, path="email-otp-c").make_token(
            self.request.user)
        return reverse_lazy("compact:verification-send-mail-otp", kwargs={"token": token})


class VerificationSendOTPMail(LoginRequiredMixin, PathTokenValidationMixin, mail_views.SendEmailView):
    """
    send an email with email verification otp
    """
    pre_path = "email-otp-c"
    template_name = "verification/user-verify-email.html"
    send_html_email = True
    email_subject = "Account Verification"
    email_template_name = "verification/user-verification-otp-mail.html"

    def get_to_email(self):
        return self.request.user.email

    def get_email_context_data(self):
        otp = get_object_or_redirect(model=OTPModel, id=self.request.session.get("OTP_ID"))
        return {"otp": otp.otp}

    def get_success_url(self):
        token = token_generator.generate_token(user_id=self.request.user.id, path="email-otp-send").make_token(
            self.request.user)
        return reverse_lazy("compact:verification-account-otp", kwargs={"token": token})


class VerifyAccountOTP(LoginRequiredMixin, PathTokenValidationMixin, otp_views.VerifyOTPView):
    """
    verify the otp provided by the user
    """
    pre_path = "email-otp-send"
    template_name = "common/user-verify-otp.html"
    model = OTPModel
    success_url = reverse_lazy("compact:verification-update-status")

    def get_user_model(self):
        return self.request.user

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update({"title": "Account Verification"})
        return context

    def get_success_url(self):
        return generate_uidb64_url(pattern_name="compact:verification-update-status", user=self.request.user)


class VerificationUpdateStatus(LoginRequiredMixin, View):
    """
    after otp verification verify the email
    """
    success_url = None

    def get_success_url(self):
        return reverse_lazy("compact:profile", kwargs={"username": self.request.user.username})

    def get(self, request):
        user = get_object_or_redirect(model=get_user_model(), id=request.user.id)
        user.email_verified = True
        user.save()
        return redirect(self.get_success_url())
