from braces.views import LoginRequiredMixin
from django.contrib.auth import get_user_model
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.views import generic, View

from users.django_mail import views as mail_views
from users.models import OTPModel
from users.otp import views as otp_views
from users.token_generators.user_token import PathTokenValidationMixin, token_generator
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
    email_template_name = "users/mail/link.html"

    def get_to_email(self):
        return self.request.user.email

    def get_email_context_data(self):
        url = generate_uidb64_url(pattern_name="users:verification-update-status", user=self.request.user,
                                  absolute=True, request=self.request)
        return {
            "url": url,
            "subject": self.email_subject,
            "content": "We received a request to verify your account. To proceed with the verification process, "
                       "please follow the link below:",
            "btn_label": "Verify",
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
    template_name = "users/mail/send-done.html"

    def get_context_data(self, *args, **kwargs):
        context = super().get_context_data()
        context.update({"message": f"An Email is sent to your email id - {self.request.user.email} with instructions"})
        return context


class VerificationSendOTPMail(LoginRequiredMixin, PathTokenValidationMixin, mail_views.SendEmailView):
    """
    send an email with email verification otp
    """
    pre_path = "email-redirect"
    send_html_email = True
    email_subject = "Account Verification"
    email_template_name = "users/mail/otp.html"

    def get_to_email(self):
        return self.request.user.email

    def get_email_context_data(self):
        otp = OTPModel.objects.get_or_create(
            user=self.request.user,
            defaults={
                "user": self.request.user,
                "otp": otp_views.generate_otp(),
            }
        )
        return {
            "otp": otp.otp,
            "subject": self.email_subject,
            "content": "You have requested to Verify your account. Please use the following OTP to proceed with the "
                       "account verification:",
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
    template_name = "users/common/verify-otp.html"
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


class VerificationUpdateStatus(LoginRequiredMixin, View):
    """
    after otp verification verify the email
    """
    success_url = None

    def get_success_url(self):
        return reverse_lazy("users:profile", kwargs={"username": self.request.user.username})

    def get(self, request):
        user = get_object_or_redirect(model=get_user_model(), id=request.user.id)
        user.objects.update(email_verified=True)
        return redirect(self.get_success_url())
