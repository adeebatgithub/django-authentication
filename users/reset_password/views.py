from django.contrib.auth import get_user_model
from django.contrib.auth import views as auth_views
from django.shortcuts import get_object_or_404
from django.urls import reverse_lazy
from django.utils.http import urlsafe_base64_decode
from django.views import generic

from users.django_mail import views as mail_views
from users.models import OTPModel
from users.otp import views as otp_views
from users.token_generators.path_token import path_token_generator, PathTokenValidationMixin
from users.token_generators.user_token import TokenValidationMixin
from . import forms
from ..utils import generate_uidb64_url


class GetEmailView(mail_views.GetEmailView):
    template_name = 'users/mail/get.html'

    def get_success_url(self):
        token = path_token_generator.generate_token(session_id=self.request.session.session_key, path="email-get")
        return reverse_lazy("users:reset-password-redirect", kwargs={"token": token})

    def get_context_data(self, **kwargs):
        return {"title": "Password Reset"}


class RedirectUserView(PathTokenValidationMixin, generic.RedirectView):
    """
    redirect the user to provide their registered email to
    send a reset link or an OTP,
    otp = True will send otp instead of link
    """
    pre_path = "email-get"
    otp = False

    def get_redirect_url(self, *args, **kwargs):
        token = path_token_generator.generate_token(session_id=self.request.session.session_key, path="reset-redirect")
        if self.otp:
            return reverse_lazy("users:reset-create-otp", kwargs={"token": token})
        return reverse_lazy("users:reset-send-link-mail", kwargs={"token": token})


class ResetSendMail(PathTokenValidationMixin, mail_views.SendEmailView):
    """
    send reset mail to the provided email if it is registered
    """
    email_subject = "Password Reset Mail"
    send_html_email = True

    def get_to_email(self):
        return self.request.session.get("USER_EMAIL")


class ResetSendLinkMail(ResetSendMail):
    """
    send password reset link to the email
    """
    pre_path = "reset-redirect"
    email_template_name = "users/mail/link.html"

    def get_email_context_data(self):
        user = get_object_or_404(get_user_model(), email=self.get_to_email())
        url = generate_uidb64_url(
            pattern_name="users:reset-password",
            user=user,
            absolute=True,
            request=self.request
        )
        context = {
            "url": url,
            "subject": self.email_subject,
            "content": "We received a request to reset your password for your account. To proceed with the password "
                       "reset process, please follow the link below:",
            "btn_label": "Reset Password",
        }
        return context

    def get_success_url(self):
        token = path_token_generator.generate_token(session_id=self.request.session.session_key, path="reset-link")
        return reverse_lazy("users:reset-mail-send-done", kwargs={"token": token})


class MailSendDoneView(PathTokenValidationMixin, generic.TemplateView):
    """
    render a template after successfully sending email with success message
    """
    pre_path = "reset-link"
    template_name = "users/mail/send-done.html"

    def get_context_data(self, *args, **kwargs):
        email = self.request.session.pop("USER_EMAIL")
        context = super().get_context_data()
        context.update({
            "message": f"An Email is sent to your email id - {email} with instructions"
        })
        return context


class ResetSendOTPMail(ResetSendMail):
    """
    send OTP for verification
    """
    pre_path = "reset-redirect"
    email_template_name = "users/mail/otp.html"

    def get_email_context_data(self):
        user = get_object_or_404(get_user_model(), email=self.get_to_email())
        otp_model = OTPModel.objects.get_or_create(
            user=user,
            defaults={
                "user": user,
                "otp": otp_views.generate_otp(),
            }
        )
        return {
            "otp": otp_model.otp,
            "subject": self.email_subject,
            "content": "You have requested to reset your password. Please use the following OTP to proceed with the "
                       "password reset:",
        }

    def get_success_url(self):
        token = path_token_generator.generate_token(session_id=self.request.session.session_key, path="reset-otp-send")
        return reverse_lazy("users:reset-otp-verify", kwargs={"token": token})


class ResetVerifyOTP(PathTokenValidationMixin, otp_views.VerifyOTPView):
    """
    verify the otp that is provided by the user
    """
    pre_path = "reset-otp-send"
    template_name = "users/common/verify-otp.html"

    def get_user_kwargs(self):
        return {"email": self.request.session.get("USER_EMAIL")}

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update({"title": "Reset Password"})
        return context

    def get_success_url(self):
        return generate_uidb64_url(pattern_name="users:reset-password", user=self.get_user_model())


class PasswordResetView(TokenValidationMixin, auth_views.PasswordResetConfirmView):
    """
    password reset
    """
    form_class = forms.PasswordResetForm
    success_url = reverse_lazy("users:reset-password-done")
    template_name = "users/password-reset/password-reset.html"

    def get_user(self):
        user_id = urlsafe_base64_decode(self.kwargs['uidb64'])
        return get_object_or_404(get_user_model(), id=user_id)


class PasswordResetDoneView(generic.TemplateView):
    """
    render a template after successfully password reset
    """
    template_name = "users/password-reset/password-reset-done.html"
