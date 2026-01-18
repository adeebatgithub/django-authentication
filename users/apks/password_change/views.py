from django.conf import settings
from django.contrib.auth import logout, get_user_model
from django.contrib.auth import views as auth_views
from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse_lazy
from django.views import generic

from users.utilities.mailing import views as mail_views
from users.utilities.otp import views as otp_views
from users.models import OTPModel
from users.utilities.token.user_token import TokenValidationMixin, token_generator, PathTokenValidationMixin
from users.utils import generate_uidb64_url
from . import forms


class RedirectUserView(LoginRequiredMixin, generic.RedirectView):
    """
    redirect to send email to the user a password change link or a verification OTP,
    otp = True will send an otp instead of link
    """
    otp = settings.EMAIL_OTP_NOT_LINK

    def get_redirect_url(self, *args, **kwargs):
        token = token_generator.generate_token(user_id=self.request.user.id, path="change-redirect").make_token(
            self.request.user)
        if self.otp:
            return reverse_lazy("users:change-send-otp-mail", kwargs={"token": token})
        return reverse_lazy("users:change-send-link-mail", kwargs={"token": token})


class ChangeSendMail(LoginRequiredMixin, PathTokenValidationMixin, mail_views.SendEmailView):
    """
    send password change email to user's email
    """
    email_subject = "Password Change Mail"
    send_html_email = True

    def get_to_email(self):
        return self.request.user.email


class ChangeSendLinkMail(ChangeSendMail):
    """
    send password change link to the user's email
    """
    pre_path = "change-redirect"
    email_template_name = "users/password-change/link.html"

    def get_email_context_data(self):
        url = generate_uidb64_url(
            pattern_name="users:change-password",
            user=self.request.user,
            absolute=True,
            request=self.request
        )
        context = {
            "url": url,
            "user": self.request.user,
        }
        self.request.session["USER_EMAIL_ID"] = self.get_to_email()
        return context

    def get_success_url(self):
        token = token_generator.generate_token(user_id=self.request.user.id, path="mail-send").make_token(
            self.request.user)
        return reverse_lazy("users:change-mail-send-done", kwargs={"token": token})


class ChangeResendOTPMail(LoginRequiredMixin, generic.RedirectView):

    def get_redirect_url(self, *args, **kwargs):
        token = token_generator.generate_token(user_id=self.request.user.id, path="change-redirect").make_token(
            self.request.user)
        return reverse_lazy("users:change-send-otp-mail", kwargs={"token": token})


class ChangeSendOTPMail(ChangeSendMail):
    """
    send verification OTP to the users email
    """
    pre_path = "change-redirect"
    email_template_name = "users/password-change/otp.html"

    def get_email_context_data(self):
        otp_model = OTPModel.objects.create(
            user=self.request.user,
            otp=otp_views.generate_otp(),
        )
        return {
            "otp": otp_model.otp,
            "user": self.request.user,
        }

    def get_success_url(self):
        token = token_generator.generate_token(user_id=self.request.user.id, path="otp-send").make_token(
            self.request.user)
        return reverse_lazy("users:change-verify-otp", kwargs={"token": token})


class ChangeVerifyOTPView(LoginRequiredMixin, PathTokenValidationMixin, otp_views.VerifyOTPView):
    """
    verify the otp provided by the user
    """
    pre_path = "otp-send"
    template_name = "users/password-change/verify-otp.html"

    def get_user_model(self):
        return self.request.user

    def get_success_url(self):
        token_generator.delete_token(token=self.kwargs.get("token"))
        return generate_uidb64_url(pattern_name="users:change-password", user=self.get_user_model())


class MailSendDoneView(PathTokenValidationMixin, generic.TemplateView):
    """
    render a template after successfully sending email with success message
    """
    pre_path = "mail-send"
    template_name = "users/password-change/send-done.html"

    def get_context_data(self, *args, **kwargs):
        email = self.request.session.pop("USER_EMAIL_ID")
        context = super().get_context_data()
        context.update({
            "message": f"An Email is sent to your email id - {email} with instructions"
        })
        return context


class PasswordChangeView(LoginRequiredMixin, TokenValidationMixin, auth_views.PasswordChangeView):
    """
    change password
    """
    form_class = forms.ChangePasswordForm
    template_name = "users/password-change/password-change.html"
    logout_user = True

    def verify_email(self):
        model = get_user_model().objects.get(id=self.request.user.id)
        model.email_verified = True
        model.save()

    def get_success_url(self):
        if not self.request.user.email_verified:
            self.verify_email()

        if self.logout_user:
            logout(self.request)

        return reverse_lazy("users:login")
