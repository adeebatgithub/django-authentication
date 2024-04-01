from django.contrib.auth import views as auth_views
from django.contrib.auth.forms import UserCreationForm
from django.urls import reverse_lazy
from django.views import generic


class TestView(generic.TemplateView):
    template_name = 'user-login.html'


class RedirectToProfileView(generic.RedirectView):
    url = reverse_lazy("users:profile")


class ProfileView(generic.TemplateView):
    template_name = "user-profile.html"


class LoginView(auth_views.LoginView):
    """
    Users Login View

    redirect user to url specified in settings.LOGIN_REDIRECT_URL
    """
    template_name = "user-login.html"
    redirect_authenticated_user = True


class LogoutView(auth_views.LogoutView):
    """
    Users Logout View

    redirect user to url specified in settings.LOGOUT_REDIRECT_URL
    """
    pass


class RegisterView(generic.CreateView):
    template_name = "user-register.html"
    form_class = UserCreationForm
    success_url = reverse_lazy("users:login")
