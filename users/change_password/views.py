from django.contrib.auth import logout
from django.contrib.auth import views as auth_views
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.views import generic, View

from users.django_mail import views as mail_views
from users.models import OTPModel
from users.otp import views as otp_views
from users.token import TokenValidationMixin, token_generator, PathTokenValidationMixin
from . import forms


class RedirectUserView(LoginRequiredMixin, generic.RedirectView):
    """
    redirect to send email to the user righter a password change link
    or a verification OTP
    otp = True will send an otp instead of link
    """
    otp = False

    def get_redirect_url(self, *args, **kwargs):
        token = token_generator.generate_token(user_id=self.request.user.id, path="change-redirect").make_token(
            self.request.user)
        if self.otp:
            return reverse_lazy("users:change-create-otp", kwargs={"token": token})
        return reverse_lazy("users:change-send-link-mail", kwargs={"token": token})


class ChangeSendMail(LoginRequiredMixin, PathTokenValidationMixin, mail_views.SendEmailView):
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
    pre_path = "change-redirect"
    email_template_name = "password-change/change-link-mail.html"

    def get_email_context_data(self):
        url = mail_views.generate_uidb64_url(
            pattern_name="users:change-password",
            user=self.request.user,
            absolute=True,
            request=self.request
        )
        context = {"url": url}
        self.request.session["USER_EMAIL_ID"] = self.get_to_email()
        return context

    def get_success_url(self):
        token = token_generator.generate_token(user_id=self.request.user.id, path="mail-send").make_token(self.request.user)
        return reverse_lazy("users:change-mail-send-done", kwargs={"token": token})


class ChangeOTPCreateView(LoginRequiredMixin, PathTokenValidationMixin, View):
    pre_path = "change-redirect"

    def get_user_model(self):
        return self.request.user

    def get_success_url(self):
        token = token_generator.generate_token(user_id=self.request.user.id, path="otp-create").make_token(
            self.request.user)
        return reverse_lazy("users:change-send-otp-mail", kwargs={"token": token})

    def get(self, request, *args, **kwargs):
        user = self.get_user_model()
        otp = OTPModel(user=user, otp=otp_views.generate_otp())
        otp.save()
        request.session["OTP_ID"] = otp.id
        return redirect(self.get_success_url())


class ChangeSendOTPMail(ChangeSendMail):
    """
    send verification OTP to the users email
    """
    pre_path = "otp-create"
    email_template_name = "password-change/change-otp-mail.html"

    def get_email_context_data(self):
        id = self.request.session.pop("OTP_ID")
        otp_model = OTPModel.objects.filter(id=id).last()
        if not otp_model:
            return redirect(reverse_lazy("users:change-password-redirect"))
        return {"otp": otp_model.otp}

    def get_success_url(self):
        token = token_generator.generate_token(user_id=self.request.user.id, path="otp-send").make_token(self.request.user)
        return reverse_lazy("users:change-verify-otp", kwargs={"token": token})


class ChangeVerifyOTPView(LoginRequiredMixin, PathTokenValidationMixin, otp_views.VerifyOTPView):
    """
    verify the otp provided by the user
    """
    pre_path = "otp-send"
    template_name = "common/user-verify-otp.html"

    def get_user_model(self):
        return self.request.user

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update({"title": "Change Password"})
        return context

    def get_success_url(self):
        token_generator.delete_token(token=self.kwargs.get("token"))
        return mail_views.generate_uidb64_url(pattern_name="users:change-password", user=self.get_user_model())


class MailSendDoneView(PathTokenValidationMixin, generic.TemplateView):
    """
    render a template after successfully sending email with success message
    """
    pre_path = "mail-send"
    template_name = "common/mail-send-done.html"

    def get_context_data(self, *args, **kwargs):
        email = self.request.session.pop("USER_EMAIL_ID")
        context = super().get_context_data()
        context.update({"email": email})
        return context


class PasswordChangeView(LoginRequiredMixin, TokenValidationMixin, auth_views.PasswordChangeView):
    """
    change password
    """
    form_class = forms.ChangePasswordForm
    template_name = "password-change/user-password-change.html"
    logout_user = True

    def get_success_url(self):
        if self.logout_user:
            logout(self.request)
        return reverse_lazy("users:login")
