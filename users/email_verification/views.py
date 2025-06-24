from braces.views import LoginRequiredMixin
from django.contrib.auth import get_user_model
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.utils.http import urlsafe_base64_decode
from django.views import generic, View

from users.django_mail import views as mail_views
from users.django_otp import views as otp_views
from users.models import OTPModel
from users.token.user_token import PathTokenValidationMixin, token_generator, TokenValidationMixin
from users.utils import get_object_or_redirect, generate_uidb64_url


class RedirectUser(LoginRequiredMixin, generic.RedirectView):
    """
    redirect the user to confirm send email
    otp = True will send an otp instead of link
    """
    otp_pattern_name = "users:verification-create-otp"
    link_pattern_name = "users:verification-send-mail-link"
    otp = False

    def get_redirect_url(self):
        if self.request.user.email_verified:
            return reverse_lazy("users:profile", kwargs={"username": self.request.user.username})
        token = token_generator.generate_token(user_id=self.request.user.id, path="email-redirect").make_token(
            self.request.user)
        if self.otp:
            return reverse_lazy(self.otp_pattern_name, kwargs={"token": token})
        return reverse_lazy(self.link_pattern_name, kwargs={"token": token})


class VerificationSendLinkMail(LoginRequiredMixin, PathTokenValidationMixin, mail_views.SendEmailView):
    """
    send an email with email verification link
    """
    pre_path = "email-redirect"
    send_html_email = True
    email_subject = "Account Verification"
    email_template_name = "users/email-verification/link.html"

    def get_to_email(self):
        return self.request.user.email

    def get_email_context_data(self):
        url = generate_uidb64_url(pattern_name="users:verification-update-status", user=self.request.user,
                                  absolute=True, request=self.request)
        return {
            "url": url,
            "user": self.request.user,
        }

    def get_success_url(self):
        token = token_generator.generate_token(user_id=self.request.user.id, path="email-link-send").make_token(
            self.request.user)
        return reverse_lazy("users:verification-mail-send-done", kwargs={"token": token})


class MailSendDoneView(LoginRequiredMixin, PathTokenValidationMixin, generic.TemplateView):
    """
    render a template after successfully sending email with success message
    """
    pre_path = "email-link-send"
    template_name = "users/email-verification/send-done.html"


class VerificationResendOTPMail(LoginRequiredMixin, generic.RedirectView):

    def get_redirect_url(self):
        token = token_generator.generate_token(user_id=self.request.user.id, path="email-redirect").make_token(
            self.request.user)
        return reverse_lazy("users:verification-create-otp", kwargs={"token": token})


class VerificationSendOTPMail(LoginRequiredMixin, PathTokenValidationMixin, mail_views.SendEmailView):
    """
    send an email with email verification otp
    """
    pre_path = "email-redirect"
    send_html_email = True
    email_subject = "Account Verification"
    email_template_name = "users/email-verification/otp.html"

    def get_to_email(self):
        return self.request.user.email

    def get_email_context_data(self):
        otp = OTPModel.objects.create(
            user=self.request.user,
            otp=otp_views.generate_otp(),
        )
        return {
            "otp": otp.otp,
            "user": self.request.user,
        }

    def get_success_url(self):
        token = token_generator.generate_token(user_id=self.request.user.id, path="email-otp-send").make_token(
            self.request.user)
        return reverse_lazy("users:verification-account-otp", kwargs={"token": token})


class VerifyAccountOTP(LoginRequiredMixin, PathTokenValidationMixin, otp_views.VerifyOTPView):
    """
    verify the otp provided by the user
    """
    pre_path = "email-otp-send"
    template_name = "users/email-verification/verify-otp.html"
    model = OTPModel
    success_url = reverse_lazy("users:verification-update-status")

    def get_user_model(self):
        return self.request.user

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update({"title": "Account Verification"})
        return context

    def get_success_url(self):
        return generate_uidb64_url(pattern_name="users:verification-update-status", user=self.request.user)


class VerificationUpdateStatus(TokenValidationMixin, View):
    """
    after otp verification verify the email
    """

    def get_user(self):
        user_id = urlsafe_base64_decode(self.kwargs.get("uidb64")).decode()
        return get_object_or_redirect(model=get_user_model(), id=user_id)

    def get_success_url(self):
        return reverse_lazy("users:profile", kwargs={"username": "A"})

    def get(self, request, *args, **kwargs):
        user = self.get_user()
        user.email_verified = True
        user.save()
        return redirect(self.get_success_url())
