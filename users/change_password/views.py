from django.contrib.auth import get_user_model, logout
from django.contrib.auth import views as auth_views
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import redirect, get_object_or_404
from django.urls import reverse_lazy
from django.views import generic, View

from users.django_mail import views as mail_views
from users.models import OTPModel
from . import forms


class RedirectUserView(LoginRequiredMixin, generic.RedirectView):
    """
    redirect to send email to the user righter a password change link
    or a verification OTP
    otp = True will send an otp instead of link
    """
    otp = True

    def get_redirect_url(self, *args, **kwargs):
        if self.otp:
            return reverse_lazy("users:change-create-otp")
        return reverse_lazy("users:change-send-link-mail")


class ChangeSendMail(LoginRequiredMixin, mail_views.SendEmailView):
    """
    send password change email to user's email
    """
    template_name = "password-change/user-password-change-mail.html"
    email_subject = "Password Change Mail"
    send_html_email = True

    def get_to_email(self):
        return self.request.user.email


class ChangeSendLinkMail(ChangeSendMail):
    """
    send password change link to the user's email
    """
    email_template_name = "password-change/change-link-mail.html"
    success_url = reverse_lazy("users:change-mail-send-done")

    def get_email_context_data(self):
        url = mail_views.generate_uidb64_url(
            pattern_name="users:change-password",
            user=self.request.user,
            absolute=True,
            request=self.request
        )
        context = {"url": url}
        return context


class ChangeOTPCreateView(LoginRequiredMixin, View):
    success_url = reverse_lazy("users:change-send-otp-mail")

    def get_user_model(self):
        return self.request.user

    def get_success_url(self):
        return self.success_url

    def get(self, request, *args, **kwargs):
        user = self.get_user_model()
        otp = OTPModel(user=user, otp=mail_views.generate_otp())
        otp.save()
        request.session["OTP_ID"] = otp.id
        return redirect(self.get_success_url())


class ChangeSendOTPMail(ChangeSendMail):
    """
    send verification OTP to the users email
    """
    email_template_name = "password-change/change-otp-mail.html"
    success_url = reverse_lazy("users:change-verify-otp")

    def get_email_context_data(self):
        otp_model = get_object_or_404(OTPModel, user=self.request.session.pop("OTP_ID"))
        return {"otp": otp_model.otp}


class ChangeVerifyOTPView(LoginRequiredMixin, mail_views.VerifyOTPView):
    """
    verify the otp provided by the user
    """
    template_name = "common/user-verify-otp.html"

    def get_user_model(self):
        return self.request.user

    def get_success_url(self):
        return mail_views.generate_uidb64_url(pattern_name="users:change-password", user=self.get_user_model())


class PasswordChangeView(LoginRequiredMixin, auth_views.PasswordChangeView):
    """
    change password
    """
    form_class = forms.ChangePasswordForm
    template_name = "password-change/user-password-change.html"

    def get_success_url(self):
        logout(self.request)
        return reverse_lazy("users:login")


class MailSendDoneView(generic.TemplateView):
    """
    render a template after successfully sending email with success message
    """
    template_name = "common/mail-send-done.html"

    def get_context_data(self, *args, **kwargs):
        email = self.request.session.pop("email")
        context = super().get_context_data()
        context.update({"email": email})
        return context
