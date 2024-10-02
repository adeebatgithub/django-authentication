from braces.views import LoginRequiredMixin
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.views import generic

from compact.token import PathTokenValidationMixin, token_generator
from compact.otp import views as otp_views
from compact.django_mail import views as mail_views
from .mixins import AccessRequiredMixin
from ..models import OTPModel
from ..utils import get_object_or_redirect, generate_uidb64_url


class ProfileView(LoginRequiredMixin, AccessRequiredMixin, generic.TemplateView):
    """
    user profile page
    """
    template_name = "general/user-profile.html"

    def get(self, request, *args, **kwargs):
        if kwargs.get("username") != request.user.username:
            return redirect(reverse_lazy("compact:profile", kwargs={"username": request.user.username}))
        return super().get(request, kwargs.get("username"))


class RedirectUserView(LoginRequiredMixin, generic.RedirectView):

    def get_redirect_url(self, *args, **kwargs):
        token = token_generator.generate_token(user_id=self.request.user.id, path="profile-redirect")
        return reverse_lazy("compact:profile-otp-create", kwargs={"token", token})


class OTPCreateView(LoginRequiredMixin, PathTokenValidationMixin, otp_views.OTPCreateView):
    pre_path = "profile-redirect"

    def get_user_model(self):
        return self.request.user

    def get_success_url(self):
        token = token_generator.generate_token(user_id=self.request.user.id, path="profile-otp-c").make_token(
            self.request.user)
        return reverse_lazy("compact:profile-send-mail-otp", kwargs={"token": token})


class SendOTPMail(LoginRequiredMixin, PathTokenValidationMixin, mail_views.SendEmailView):
    """
    send an email with email verification otp
    """
    pre_path = "profile-otp-c"
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
        token = token_generator.generate_token(user_id=self.request.user.id, path="profile-otp-send").make_token(
            self.request.user)
        return reverse_lazy("compact:profile-otp", kwargs={"token": token})


class VerifyOTP(LoginRequiredMixin, PathTokenValidationMixin, otp_views.VerifyOTPView):
    """
    verify the otp provided by the user
    """
    pre_path = "profile-otp-send"
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
        return reverse_lazy("compact:profile", kwargs={"username": self.request.user.username})
