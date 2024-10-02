from django.contrib.auth import get_user_model
from django.contrib.auth import views as auth_views
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse_lazy
from django.utils.http import urlsafe_base64_decode
from django.views import generic, View

from compact.django_mail import views as mail_views
from compact.models import OTPModel
from compact.otp import views as otp_views
from compact.token import TokenValidationMixin, PathTokenValidationMixin, token_generator
from compact.utils import generate_uidb64_url
from . import forms


class GetEmailView(mail_views.GetEmailView):
    template_name = 'password-forgot/user-password-reset-mail.html'

    def get_success_url(self):
        token = token_generator.generate_token(user_id=self.request.user.id, path="email-get").make_token()
        return reverse_lazy("compact:reset-password-redirect", kwargs={"token": token})


class RedirectUserView(PathTokenValidationMixin, generic.RedirectView):
    """
    redirect the user to provide their registered email to
    send a reset link or an OTP
    otp = True will send otp instead of link
    """
    pre_path = "email-get"

    def get_redirect_url(self, *args, **kwargs):
        token = token_generator.generate_token(user_id=self.request.user.id, path="reset-redirect").make_token()
        return reverse_lazy("compact:reset-create-otp", kwargs={"token": token})


class ResetSendMail(PathTokenValidationMixin, mail_views.SendEmailView):
    """
    send reset mail to the provided email if it is registered
    """
    template_name = "password-forgot/user-password-reset-mail.html"
    email_subject = "Password Reset Mail"
    send_html_email = True

    def get_to_email(self):
        return self.request.session.get("USER_EMAIL")


class ResetOTPCreateView(PathTokenValidationMixin, View):
    pre_path = "reset-redirect"

    def get_user_model(self):
        return get_object_or_404(get_user_model(), email=self.request.session.get("USER_EMAIL"))

    def get_success_url(self):
        token = token_generator.generate_token(user_id=self.request.user.id, path="reset-otp-c").make_token()
        return reverse_lazy("compact:reset-send-otp-mail", kwargs={"token": token})

    def get(self, request, *args, **kwargs):
        user = self.get_user_model()
        otp = OTPModel(user=user, otp=otp_views.generate_otp())
        otp.save()
        request.session["OTP_ID"] = otp.id
        return redirect(self.get_success_url())


class ResetSendOTPMail(ResetSendMail):
    """
    send OTP for verification
    """
    pre_path = "reset-otp-c"
    email_template_name = "password-forgot/reset-otp-mail.html"

    def get_email_context_data(self):
        otp_model = get_object_or_404(OTPModel, id=self.request.session.pop("OTP_ID"))
        return {"otp": otp_model.otp}

    def get_success_url(self):
        token = token_generator.generate_token(user_id=self.request.user.id, path="reset-otp-send").make_token()
        return reverse_lazy("compact:reset-otp-verify", kwargs={"token": token})


class ResetVerifyOTP(PathTokenValidationMixin, otp_views.VerifyOTPView):
    """
    verify the otp that is provided by the user
    """
    pre_path = "reset-otp-send"
    template_name = "common/user-verify-otp.html"

    def get_user_kwargs(self):
        return {"email": self.request.session.get("USER_EMAIL")}

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update({"title": "Reset Password"})
        return context

    def get_success_url(self):
        return generate_uidb64_url(pattern_name="compact:reset-password", user=self.get_user_model())


class PasswordResetView(TokenValidationMixin, auth_views.PasswordResetConfirmView):
    """
    password reset
    """
    form_class = forms.PasswordResetForm
    success_url = reverse_lazy("compact:reset-password-done")
    template_name = "password-forgot/user-password-reset.html"

    def get_user(self):
        user_id = urlsafe_base64_decode(self.kwargs['uidb64'])
        return get_object_or_404(get_user_model(), id=user_id)


class PasswordResetDoneView(generic.TemplateView):
    """
    render a template after successfully password reset
    """
    template_name = "password-forgot/user-password-reset-done.html"
