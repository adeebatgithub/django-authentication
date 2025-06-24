from django.contrib.auth import views as auth_views
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.views import generic

from users.second_factor_auth.mixins import MultiFactorVerificationRequiredMixin
from . import forms, base_views


class RedirectUserView(base_views.RedirectUserView):
    """
    Users Redirect View, redirect logged-in user
    """

    def get_pattern_name(self):
        return reverse_lazy("users:profile", kwargs={"username": self.request.user.username})


class ProfileView(LoginRequiredMixin, MultiFactorVerificationRequiredMixin, generic.TemplateView):
    """
    user profile page
    """
    template_name = "users/general/profile.html"

    def get(self, request, *args, **kwargs):
        if kwargs.get("username") != request.user.username:
            return redirect(reverse_lazy("users:profile", kwargs={"username": request.user.username}))
        return super().get(request, kwargs.get("username"))


class LoginView(auth_views.LoginView):
    """
    Users Login View

    redirect user to url specified in settings.LOGIN_REDIRECT_URL
    set settings.LOGIN_REDIRECT_URL to 'users:redirect-logged-user'
    to redirect user based on the group or role
    """
    template_name = "users/general/login.html"
    form_class = forms.UserLoginForm
    redirect_authenticated_user = True
    pattern_name = "users:redirect-user"

    def get_redirect_url(self):
        return reverse_lazy(self.pattern_name)

    def form_valid(self, form):
        form.reset_login_attempts()
        self.request.session.cycle_key()
        return super().form_valid(form)

    def form_invalid(self, form):
        if "account_locked" in form.error_messages:
            return redirect("users:get-email-lock")
        return super().form_invalid(form)


class LogoutView(auth_views.LogoutView):
    """
    Users Logout View

    redirect user to login page
    """
    next_page = "users:login"
    http_method_names = ["get", "post", "put"]
    success_url = reverse_lazy("users:login")

    def get_success_url(self):
        return self.success_url

    def get(self, request, *args, **kwargs):
        request.user.un_verify_second_factor()
        return super().post(request, *args, **kwargs)


class RegisterView(base_views.BaseUserRegistrationView):
    """
    User creation/registration view

    regular user is created and redirected to add the user in to a group
    """
    template_name = "users/general/register.html"
    success_url = reverse_lazy("users:login")

    def get_success_url(self, *args, **kwargs):
        self.request.session["user_id"] = self.object.id
        return self.success_url


class ChangeUsername(base_views.UpdateUser):
    form_class = forms.ChangeUsernameForm
    title = "Username"


class ChangeFullname(base_views.UpdateUser):
    form_class = forms.ChangeFullnameForm
    title = "Fullname"


class ChangeEmail(base_views.UpdateUser):
    form_class = forms.ChangeEmailForm
    title = "Email"

    def change_email_status(self):
        self.object.update(email_verified=False)

    def get_success_url(self):
        self.change_email_status()
        return super().get_success_url()
