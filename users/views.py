from django.contrib.auth import get_user_model, logout
from django.contrib.auth import views as auth_views
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import ImproperlyConfigured
from django.shortcuts import get_object_or_404
from django.urls import reverse_lazy
from django.views import generic

from . import forms
from .base_views import AddToGroup, AddRole
from .django_mail.views import SendEmailView, VerifyOTPView, generate_reset_url, OTPCreateView
from .models import OTPModel


def test(request):
    print(request.get_full_path())


class ProfileView(LoginRequiredMixin, generic.TemplateView):
    """
    user profile page
    """
    template_name = "user-profile.html"


class LoginView(auth_views.LoginView):
    """
    Users Login View

    redirect user to url specified in settings.LOGIN_REDIRECT_URL
    set settings.LOGIN_REDIRECT_URL to 'users:redirect-logged-user'
    to redirect user based on the group or role
    """
    template_name = "user-login.html"
    form_class = forms.UserLoginForm
    redirect_authenticated_user = True
    pattern_name = "users:redirect-user"

    def get_redirect_url(self):
        return reverse_lazy(self.pattern_name)


class RedirectUserView(LoginRequiredMixin, generic.RedirectView):
    """
    users are redirected based on role or group
    to redirect users based on group define 'group_and_url'
    to redirect users based on role define 'role_and_url'
    to redirect all users to same url or to redirect users who are not in any group, define 'pattern_name'
    """
    permanent = True
    group_and_url = {
        # group name: redirect url
        # customer: reverse_lazy("customer-home")
    }
    role_and_url = {
        # role name: redirect url
        # User.staff: reverse_lazy("staff-home")
    }
    pattern_name = reverse_lazy("users:profile")
    redirect_superuser_to_admin = True

    def get_group_and_url(self):
        # if self.group_and_url:
        #    return self.group_and_url
        return {"example": reverse_lazy("users:profile", kwargs={"username": self.request.user.username})}

    def get_role_and_url(self):
        if self.role_and_url:
            return self.role_and_url

    def get_pattern_name(self):
        # if self.pattern_name:
        #    return self.pattern_name
        return reverse_lazy("users:profile", kwargs={"username": self.request.user.username})

    def is_member(self, user, group):
        return user.groups.filter(name=group).exists()

    def get_redirect_url(self, *args, **kwargs):
        if self.redirect_superuser_to_admin:
            if self.request.user.is_superuser:
                return "/admin"

        if self.get_group_and_url():
            print(self.get_group_and_url())
            for group, url in self.get_group_and_url().items():
                if self.is_member(self.request.user, group):
                    return url

        if self.get_role_and_url():
            print(self.get_role_and_url())
            for role, url in self.get_role_and_url().items():
                if self.request.user.role == role:
                    return url

        if self.get_pattern_name():
            return self.get_pattern_name()

        raise ImproperlyConfigured(
            "RedirectLoggedUser needs dict of 'group_and_url' or 'role_and_url' or 'pattern_name'")


class LogoutView(auth_views.LogoutView):
    """
    Users Logout View

    redirect user to login page
    """
    next_page = "users:login"


class RegisterView(generic.CreateView):
    """
    User creation/registration view

    regular user is created and redirected to add the user in to a group
    """
    model = get_user_model()
    template_name = "user-register.html"
    form_class = forms.UserRegistrationForm
    success_url = reverse_lazy("users:add-example-role")

    def get_success_url(self, *args, **kwargs):
        self.request.session["user_id"] = self.object.id
        return self.success_url


class AddExampleRole(AddRole):
    """
    give users  the specified role
    """
    role = get_user_model().EXAMPLE_ROLE


class AddToExampleGroup(AddToGroup):
    """
    add users to the specified group
    """
    group_name = "example"


class PasswordResetRedirectView(generic.RedirectView):
    """
    redirect the user to provide their registered email to
    send a reset link or an OTP
    """
    url = reverse_lazy("users:send-reset-link-mail")


class SendResetMail(SendEmailView):
    """
    send reset mail to the provided email if it is registered
    """
    template_name = "user-password-reset-mail.html"
    success_url = reverse_lazy("users:mail-send-done")
    email_subject = "Password Reset Mail"
    send_html_email = True

    def get_to_email(self):
        return self.request.session.get("email")


class SendResetLinkMail(SendResetMail):
    """
    send password reset link to the email
    """
    email_template_name = "reset-mail.html"

    def get_email_context_data(self):
        user = get_object_or_404(get_user_model(), email=self.request.session.get("email"))
        url = generate_reset_url(pattern_name="users:reset-password", user=user, absolute=True, request=self.request)
        context = {"url": url}
        return context


class CreateResetOTP(OTPCreateView):
    model = OTPModel
    success_url = reverse_lazy("users:send-reset-otp-mail")

    def get_user_kwargs(self):
        return {"email": self.request.session.get("email")}


class SendResetOTPMail(SendResetMail):
    """
    send OTP for verification
    """
    success_url = reverse_lazy("users:verify-password-reset-otp")

    def get_email_context_data(self):
        user = get_object_or_404(get_user_model(), email=self.request.session.get("email"))
        otp_model = get_object_or_404(OTPModel, user=user)
        return {"otp": otp_model.otp}


class VerifyResetOTPView(VerifyOTPView):
    template_name = "user-verify-otp.html"

    def get_user_kwargs(self):
        return {"email": self.request.session.get("email")}

    def get_success_url(self):
        return generate_reset_url(pattern_name="users:password-reset", user=get_user_model())


class PasswordResetView(auth_views.PasswordResetConfirmView):
    """
    password reset
    """
    form_class = forms.PasswordResetForm
    success_url = reverse_lazy("users:reset-password-done")
    template_name = "user-password-reset.html"


class PasswordResetDoneView(generic.TemplateView):
    """
    render a template after successfully password reset
    """
    template_name = "user-password-reset-done.html"


class PasswordChangeRedirectView(generic.RedirectView):
    """
    redirect to send email to the user righter a password change link
    or a verification OTP
    """
    pattern_name = "users:send-password-change-mail"


class SendChangeMail(LoginRequiredMixin, SendEmailView):
    """
    send password change email to user's email
    """
    template_name = "user-password-change-mail.html"
    success_url = reverse_lazy("users:change-mail-send-done")
    email_subject = "Password Change Mail"
    send_html_email = True
    email_template_name = "password-change-mail.html"

    def get_to_email(self):
        return self.request.user.email


class SendChangeLinkMail(SendChangeMail):
    """
    send password change link to the user's email
    """

    def get_email_context_data(self):
        url = generate_reset_url(pattern_name="users:change-password", user=self.request)
        context = {"url": url}
        return context


class CreateChangeOTP(OTPCreateView):
    model = OTPModel
    success_url = reverse_lazy("users:send-change-otp-mail")

    def get_user_kwargs(self):
        return {"email": self.request.user.email}


class SendChangeOTPMail(SendChangeMail):
    """
    send verification OTP to the users email
    """
    success_url = reverse_lazy("users:verify-password-change-otp")

    def get_email_context_data(self):
        user = get_object_or_404(get_user_model(), email=self.request.session.get("email"))
        otp_model = get_object_or_404(OTPModel, user=user)
        return {"otp": otp_model.otp}


class VerifyChangeOTPView(VerifyOTPView):
    template_name = "user-verify-otp.html"

    def get_user_model(self):
        return self.request.user

    def get_success_url(self):
        return generate_reset_url(pattern_name="users:change-password", user=get_user_model())


class PasswordChangeView(auth_views.PasswordChangeView):
    """
    change password
    """
    form_class = forms.ChangePasswordForm
    template_name = "user-password-change.html"

    def get_success_url(self):
        logout(self.request)
        return reverse_lazy("users:login")


class MailSendDoneView(generic.TemplateView):
    """
    render a template after successfully sending email with success message
    """
    template_name = "mail-send-done.html"

    def get_context_data(self, *args, **kwargs):
        email = self.request.session.pop("email")
        context = super().get_context_data()
        context.update({"email": email})
        return context
