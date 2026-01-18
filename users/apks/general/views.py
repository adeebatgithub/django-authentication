from django.contrib.auth import views as auth_views
from django.shortcuts import redirect
from django.urls import reverse_lazy

from . import forms, base_views


class RedirectUserView(base_views.RedirectUserView):
    """
    Users Redirect View, redirect logged-in user
    """

    def get_redirect_url(self):
        return reverse_lazy("users:profile", kwargs={"username": self.request.user.username})


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
    http_method_names = ["get", "post"]
    success_url = reverse_lazy("users:login")

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
