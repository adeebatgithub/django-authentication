from django.contrib.auth import views as auth_views
from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse_lazy
from django.views import generic, View
from django.core.exceptions import ImproperlyConfigured
from django.shortcuts import get_object_or_404, redirect
from django.conf import settings
from django.contrib.auth.models import Group
from django.contrib.auth import get_user_model, logout
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator

from . import forms
from .django_email import SendEmailView


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


class AddRole(View):
    """
    base implimentation of adding a role to the user
    inherit and define 'role' and 'success_url'
    """
    role = None  # User.role
    success_url = reverse_lazy("users:add-to-example-group")

    def get_role(self):
        if self.role:
            return self.role
        raise ImproperlyConfigured(f"AddRole need a 'role'")

    def get_success_url(self):
        if self.success_url:
            return self.success_url
        raise ImproperlyConfigured(f"AddRole needs 'success_url'")

    def get_user_object(self):
        return get_object_or_404(get_user_model(), id=self.request.session.get("user_id"))

    def get(self, request, *args, **kwargs):
        model = self.get_user_object()
        model.role = self.get_role()
        model.save()
        return redirect(self.get_success_url())


class AddToGroup(View):
    """
    base implimentation of adding a user to a gruop
    inherit and define 'group_name' add 'success_url'
    """
    group_name = None
    model = Group
    success_url = reverse_lazy("users:login")

    def get_group_model(self):
        if self.group_name:
            return get_object_or_404(self.model, name=self.group_name)
        raise ImproperlyConfigured(f"AddToGroup needs either a definition of 'group_name'")

    def get_success_url(self):
        if self.success_url:
            return self.success_url
        raise ImproperlyConfigured(f"AddToGroup needs 'success_url'")

    def get_user_model(self, **kwargs):
        user_model = get_user_model()
        return get_object_or_404(user_model, **kwargs)

    def get(self, request, *args, **kwargs):
        group = self.get_group_model()
        user_id = request.session.pop("user_id")
        user = self.get_user_model(id=user_id)
        user.groups.add(group)
        return redirect(self.get_success_url())


class AddExampleRole(AddRole):
    role = get_user_model().EXAMPLE_ROLE


class AddToExampleGroup(AddToGroup):
    group_name = "example"


class PasswordResetRedirectView(generic.RedirectView):
    url = reverse_lazy("users:send-reset-mail")


class SendResetMail(SendEmailView):
    template_name = "user-password-reset-mail.html"
    success_url = reverse_lazy("users:mail-send-done")
    email_subject = "Password Reset Mail"
    send_html_email = True
    email_template_name = "reset-mail.html"

    def get_to_email(self):
        return self.request.session.get("email")

    def get_email_context_data(self):
        user = get_object_or_404(get_user_model(), email=self.request.session.get("email"))
        uidb64 = urlsafe_base64_encode(force_bytes(user.id))
        token = default_token_generator.make_token(user)
        url = reverse_lazy("users:reset-password", kwargs={"uidb64": uidb64, "token": token})
        uri = self.request.build_absolute_uri(url)
        context = {"url": uri}
        return context


class MailSendDoneView(generic.TemplateView):
    template_name = "mail-send-done.html"

    def get_context_data(self, *args, **kwargs):
        email = self.request.session.pop("email")
        context = super().get_context_data()
        context.update({"email": email})
        return context


class PasswordResetView(auth_views.PasswordResetConfirmView):
    form_class = forms.PasswordResetForm
    success_url = reverse_lazy("users:reset-password-done")
    template_name = "user-password-reset.html"


class PasswordResetDoneView(generic.TemplateView):
    template_name = "user-password-done.html"
