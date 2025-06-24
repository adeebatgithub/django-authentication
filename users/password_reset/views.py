from django.contrib.auth import get_user_model
from django.contrib.auth import views as auth_views
from django.shortcuts import get_object_or_404
from django.urls import reverse_lazy
from django.utils.http import urlsafe_base64_decode
from django.views import generic

from users.django_mail import views as mail_views
from users.django_otp import views as otp_views
from users.models import OTPModel
from users.token.path_token import path_token_generator, PathTokenValidationMixin
from . import forms
from ..utils import generate_uidb64_url


class GetEmailView(mail_views.GetEmailView):
    template_name = 'users/password-reset/get-mail.html'

    def get_success_url(self):
        token = path_token_generator.generate_token(session_id=self.request.session.session_key, path="email-get")
        return reverse_lazy("users:reset-password-redirect", kwargs={"token": token})

    def get_context_data(self, **kwargs):
        context = super(GetEmailView, self).get_context_data(**kwargs)
        context["title"] = "Password Reset"
        return context


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
    email_template_name = "users/password-reset/link.html"

    def get_email_context_data(self):
        user = get_object_or_404(get_user_model(), email=self.get_to_email())
        url = generate_uidb64_url(
            pattern_name="users:reset-password",
            user=user,
            absolute=True,
            request=self.request,
            default_generator=True
        )
        context = {
            "url": url,
            "user": self.request.user,
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
    template_name = "users/password-reset/send-done.html"

    def get_context_data(self, *args, **kwargs):
        email = self.request.session.pop("USER_EMAIL")
        context = super().get_context_data()
        context.update({
            "message": f"An Email is sent to your email id - {email} with instructions"
        })
        return context


class ResetResendOTPMail(generic.RedirectView):

    def get_redirect_url(self, *args, **kwargs):
        token = path_token_generator.generate_token(session_id=self.request.session.session_key, path="reset-redirect")
        return reverse_lazy("users:reset-create-otp", kwargs={"token": token})


class ResetSendOTPMail(ResetSendMail):
    """
    send OTP for verification
    """
    pre_path = "reset-redirect"
    email_template_name = "users/password-reset/otp.html"

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
        token = path_token_generator.generate_token(session_id=self.request.session.session_key, path="reset-otp-send")
        return reverse_lazy("users:reset-otp-verify", kwargs={"token": token})


class ResetVerifyOTP(PathTokenValidationMixin, otp_views.VerifyOTPView):
    """
    verify the otp that is provided by the user
    """
    pre_path = "reset-otp-send"
    template_name = "users/password-reset/verify-otp.html"

    def get_user_kwargs(self):
        return {"email": self.request.session.get("USER_EMAIL")}

    def get_success_url(self):
        return generate_uidb64_url(pattern_name="users:reset-password", user=self.get_user_model(),
                                   default_generator=True)


class PasswordResetView(auth_views.PasswordResetConfirmView):
    """
    password reset
    """
    form_class = forms.PasswordResetForm
    success_url = reverse_lazy("users:reset-password-done")
    template_name = "users/password-reset/password-reset.html"

    def get_user(self, *args):
        user_id = urlsafe_base64_decode(self.kwargs['uidb64'])
        return get_object_or_404(get_user_model(), id=user_id)


class PasswordResetDoneView(generic.TemplateView):
    """
    render a template after successfully password reset
    """
    template_name = "users/password-reset/password-reset-done.html"
