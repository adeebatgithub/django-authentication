from django.contrib.auth import get_user_model
from django.contrib.auth import views as auth_views
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse_lazy
from django.views import generic, View

from users.django_mail import views as mail_views
from users.models import OTPModel
from . import forms


class GetEmailView(mail_views.GetEmailView):
    template_name = 'password-forgot/user-password-reset-mail.html'
    success_url = reverse_lazy("users:reset-password-redirect")


class RedirectUserView(generic.RedirectView):
    """
    redirect the user to provide their registered email to
    send a reset link or an OTP
    otp = True will send otp instead of link
    """
    otp = False

    def get_redirect_url(self, *args, **kwargs):
        if self.otp:
            return reverse_lazy("users:reset-create-otp")
        return reverse_lazy("users:reset-send-link-mail")


class ResetSendMail(mail_views.SendEmailView):
    """
    send reset mail to the provided email if it is registered
    """
    template_name = "password-forgot/user-password-reset-mail.html"
    success_url = reverse_lazy("users:reset-mail-send-done")
    email_subject = "Password Reset Mail"
    send_html_email = True

    def get_to_email(self):
        return self.request.session.get("USER_EMAIL")


class ResetSendLinkMail(ResetSendMail):
    """
    send password reset link to the email
    """
    email_template_name = "password-forgot/reset-link-mail.html"

    def get_email_context_data(self):
        user = get_object_or_404(get_user_model(), email=self.request.session.get("email"))
        url = mail_views.generate_uidb64_url(pattern_name="users:reset-password", user=user, absolute=True,
                                             request=self.request)
        context = {"url": url}
        return context


class ResetOTPCreateView(View):

    def get_user_model(self):
        return get_object_or_404(get_user_model(), email=self.request.session.get("USER_EMAIL"))

    def get_success_url(self):
        return reverse_lazy("users:reset-send-otp-mail")

    def get(self, request, *args, **kwargs):
        user = self.get_user_model()
        otp = OTPModel(user=user, otp=mail_views.generate_otp())
        otp.save()
        request.session["OTP_ID"] = otp.id
        return redirect(self.get_success_url())


class ResetSendOTPMail(ResetSendMail):
    """
    send OTP for verification
    """
    email_template_name = "password-forgot/reset-otp-mail.html"
    success_url = reverse_lazy("users:reset-otp-verify")

    def get_email_context_data(self):
        otp_model = get_object_or_404(OTPModel, id=self.request.session.pop("OTP_ID"))
        return {"otp": otp_model.otp}


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


class ResetVerifyOTP(mail_views.VerifyOTPView):
    """
    verify the otp that is provided by the user
    """
    template_name = "common/user-verify-otp.html"

    def get_user_kwargs(self):
        return {"email": self.request.session.get("USER_EMAIL")}

    def get_success_url(self):
        return mail_views.generate_uidb64_url(pattern_name="users:reset-password", user=self.get_user_model())


class PasswordResetView(auth_views.PasswordResetConfirmView):
    """
    password reset
    """
    form_class = forms.PasswordResetForm
    success_url = reverse_lazy("users:reset-password-done")
    template_name = "password-forgot/user-password-reset.html"


class PasswordResetDoneView(generic.TemplateView):
    """
    render a template after successfully password reset
    """
    template_name = "password-forgot/user-password-reset-done.html"
