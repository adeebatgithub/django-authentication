from django.contrib.auth import get_user_model, logout
from django.contrib.auth import views as auth_views
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import ImproperlyConfigured
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse_lazy
from django.utils.http import urlsafe_base64_decode
from django.views import generic, View
from django.conf import settings

from . import forms
from .base_views import AddToGroup, AddRole, RoleChangeView
from .django_mail.mixins import SendEmailMixin
from .django_mail.views import SendEmailView, VerifyOTPView, generate_uidb64_url, generate_otp
from .models import OTPModel


def test(request):
    print(request.get_full_path())





class EmailVerificationRedirect(LoginRequiredMixin, generic.RedirectView):
    """
    redirect the user to confirm send email
    otp = True will send an otp instead of link
    """
    otp_pattern_name = "users:send-verification-otp"
    link_pattern_name = "users:send-verification-link"
    otp = False

    def get_redirect_url(self):
        if self.request.user.email_verified:
            return reverse_lazy("users:profile", kwargs={"username": self.request.user.username})
        if self.otp:
            return reverse_lazy(self.otp_pattern_name)
        return reverse_lazy(self.link_pattern_name)


class SendVerificationLinkMail(LoginRequiredMixin, SendEmailView):
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
        url = generate_uidb64_url(
            pattern_name="users:account-verification-link",
            user=self.request.user,
            absolute=True,
            request=self.request
        )
        return {"url": url}

    def post(self, request):
        self.send_mail()
        request.session["email"] = self.get_to_email()
        return redirect(self.get_success_url())


class VerifyAccountLink(View):
    """
    verify the email
    """

    def get(self, request, uidb64, **kwargs):
        user_id = urlsafe_base64_decode(uidb64)
        user = get_object_or_404(get_user_model(), id=user_id)
        user.email_verified = True
        user.save()
        return redirect(reverse_lazy("users:profile", kwargs={"username": user.username}))


class SendVerificationOTPMail(LoginRequiredMixin, SendEmailView):
    """
    send an email with email verification otp
    """
    template_name = "verification/user-verify-email.html"
    success_url = reverse_lazy("users:verify-verification-otp")
    send_html_email = True
    email_subject = "Account Verification"
    email_template_name = "user-verification-otp-mail.html"

    def get_to_email(self):
        return self.request.user.email

    def get_email_context_data(self):
        otp = get_object_or_404(OTPModel, user=self.request.user)
        return {"otp": otp.otp}

    def post(self, request):
        otp = OTPModel(user=request.user, otp=generate_otp())
        otp.save()
        self.send_mail()
        return redirect(self.get_success_url())


class VerifyAccountOTP(LoginRequiredMixin, VerifyOTPView):
    """
    verify the otp provided by the user
    """
    template_name = "common/user-verify-otp.html"
    model = OTPModel
    success_url = reverse_lazy("users:update-verification-status")

    def get_user_model(self):
        return self.request.user


class UpdateVerificationStatus(LoginRequiredMixin, View):
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


class SendRoleChangeMail(SendEmailMixin, View):
    to_email = settings.EMAIL_HOST_USER
    email_subject = "Role Change Request"
    send_html_email = True
    email_template_name = "role/user-role-change-mail.html"
    success_url = reverse_lazy("users:send-role-change-mail-done")

    def get_success_url(self):
        return self.success_url

    def get_from_email(self):
        return self.request.user.email

    def get_email_context_data(self):
        accept_url = generate_uidb64_url(
            pattern_name="users:change-role",
            user=self.request.user,
            absolute=True,
            request=self.request
        )
        decline_url = generate_uidb64_url(
            pattern_name="users:change-role-fail",
            user=self.request.user,
            absolute=True,
            request=self.request,
            role=self.kwargs.get("role")
        )
        return {
            "username": self.request.user.username,
            "email": self.request.user.email,
            "role": self.kwargs.get("role"),
            "accept_url": accept_url,
            "decline_url": decline_url,
        }

    def get(self, request, **kwargs):
        role = kwargs.get("role")
        self.send_mail()
        return redirect(self.get_success_url())


class RoleChangeMailSendDone(LoginRequiredMixin, generic.TemplateView):
    template_name = "role/user-role-chane-mail-send-done.html"


class RoleChangeToStaff(RoleChangeView):
    role_name = get_user_model().STAFF
    group_name = "staff"
    success_url = reverse_lazy("users:change-role-done-mail")


class RoleChangeDecline(generic.RedirectView):

    def get_redirect_url(self, *args, **kwargs):
        user_id = urlsafe_base64_decode(self.kwargs.get("uidb64"))
        user = get_object_or_404(get_user_model(), id=user_id)
        self.request.session["USER_NAME"] = user.username
        self.request.session["USER_EMAIL"] = user.email
        self.request.session["ROLE"] = self.kwargs.get("role")
        return reverse_lazy("users:change-role-fail-mail")


class RoleChangeDoneMail(SendEmailMixin, View):
    email_subject = "Role Change Done"
    send_html_email = True
    email_template_name = "role/user-role-change-done-mail.html"
    success_url = reverse_lazy("users:role-change-done")

    def get_success_url(self):
        return self.success_url
    def get_to_email(self):
        return self.request.session.pop("USER_EMAIL")

    def get_email_context_data(self):
        return {"message": "your role change request has been verified and changed successfully"}

    def get(self, request, *args, **kwargs):
        self.send_mail()
        return redirect(self.get_success_url())


class RoleChangeFailMail(LoginRequiredMixin, SendEmailMixin, View):
    email_subject = "Role Change Failed"
    send_html_email = True
    email_template_name = "role/user-role-change-done-mail.html"
    success_url = reverse_lazy("users:role-change-fail")

    def get_success_url(self):
        return self.success_url

    def get_to_email(self):
        return self.request.session.pop("USER_EMAIL")

    def get_email_context_data(self):
        return {"message": "your role change request has been declined by the admin"}

    def get(self, request, *args, **kwargs):
        self.send_mail()
        return redirect(self.get_success_url())


class RoleChangeDone(generic.TemplateView):
    template_name = "role/user-role-change-done.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update({
            "username": self.request.session.pop("USER_NAME"),
            "role": self.request.session.pop("ROLE"),
            "status": "accepted",
        })
        return context


class RoleChangeDeclined(generic.TemplateView):
    template_name = "role/user-role-change-done.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update({
            "username": self.request.session.pop("USER_NAME"),
            "role": self.request.session.pop("ROLE"),
            "status": "declined",
        })
        return context
