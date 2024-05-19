from braces.views import LoginRequiredMixin
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse_lazy
from django.utils.http import urlsafe_base64_decode
from django.views import generic, View

from users.django_mail import views as mail_views
from users.otp import views as otp_views
from users.models import OTPModel
from users.token import TokenValidationMixin


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
        if self.otp:
            return reverse_lazy(self.otp_pattern_name)
        return reverse_lazy(self.link_pattern_name)


class VerificationSendLinkMail(LoginRequiredMixin, mail_views.SendEmailView):
    """
    send an email with email verification link
    """
    template_name = "verification/user-verify-email.html"
    success_url = reverse_lazy("users:verification-mail-send-done")
    send_html_email = True
    email_subject = "Account Verification"
    email_template_name = "verification/user-verification-link-mail.html"

    def get_to_email(self):
        return self.request.user.email

    def get_email_context_data(self):
        url = mail_views.generate_uidb64_url(
            pattern_name="users:verification-account-link",
            user=self.request.user,
            absolute=True,
            request=self.request
        )
        return {"url": url}


class VerifyAccountLink(TokenValidationMixin, View):
    """
    verify the email
    """

    def get_user_object(self):
        user_id = urlsafe_base64_decode(self.kwargs['uidb64'])
        return get_object_or_404(get_user_model(), id=user_id)

    def get(self, request, **kwargs):
        user = self.get_user_object()
        user.email_verified = True
        user.save()
        return redirect(reverse_lazy("users:profile", kwargs={"username": user.username}))


class VerificationOTPCreateView(LoginRequiredMixin, otp_views.OTPCreateView):
    success_url = reverse_lazy("users:verification-send-mail-otp")

    def get_user_model(self):
        return self.request.user


class VerificationSendOTPMail(LoginRequiredMixin, mail_views.SendEmailView):
    """
    send an email with email verification otp
    """
    template_name = "verification/user-verify-email.html"
    success_url = reverse_lazy("users:verification-account-otp")
    send_html_email = True
    email_subject = "Account Verification"
    email_template_name = "verification/user-verification-otp-mail.html"

    def get_to_email(self):
        return self.request.user.email

    def get_email_context_data(self):
        otp = get_object_or_404(OTPModel, id=self.request.session.get("OTP_ID"))
        return {"otp": otp.otp}


class VerifyAccountOTP(LoginRequiredMixin, otp_views.VerifyOTPView):
    """
    verify the otp provided by the user
    """
    template_name = "common/user-verify-otp.html"
    model = OTPModel
    success_url = reverse_lazy("users:verification-update-status")

    def get_user_model(self):
        return self.request.user

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update({"title": "Account Verification"})
        return context


class VerificationUpdateStatus(LoginRequiredMixin, View):
    """
    after otp verification verify the email
    """
    success_url = None

    def get_success_url(self):
        return reverse_lazy("users:profile", kwargs={"username": self.request.user.username})

    def get(self, request):
        user = get_object_or_404(get_user_model(), id=request.user.id)
        user.email_verified = True
        user.save()
        return redirect(self.get_success_url())


class MailSendDoneView(LoginRequiredMixin, generic.TemplateView):
    """
    render a template after successfully sending email with success message
    """
    template_name = "common/mail-send-done.html"

    def get_context_data(self, *args, **kwargs):
        context = super().get_context_data()
        context.update({"email": self.request.user.email})
        return context
