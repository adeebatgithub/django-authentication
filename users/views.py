from django.contrib.auth import views as auth_views
from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse_lazy
from django.views import generic, View
from django.core.exceptions import ImproperlyConfigured
from django.shortcuts import get_object_or_404

from . import forms


class TestView(generic.TemplateView):
    template_name = 'user-login.html'


class RedirectToProfileView(LoginRequiredMixin, generic.RedirectView):

    def get_redirect_url(self, *args, **kwargs):
        return reverse_lazy("users:profile", kwargs={"username": self.request.user.username})


class ProfileView(LoginRequiredMixin, generic.TemplateView):
    template_name = "user-profile.html"


class LoginView(auth_views.LoginView):
    """
    Users Login View

    redirect user to url specified in settings.LOGIN_REDIRECT_URL
    """
    template_name = "user-login.html"
    form_class = forms.UserLoginForm
    redirect_authenticated_user = True


class LogoutView(auth_views.LogoutView):
    """
    Users Logout View

    redirect user to url specified in settings.LOGOUT_REDIRECT_URL
    """
    pass


class RegisterView(generic.CreateView):
    """
    User creation/registration view

    regular user is created and redirected to add the user in to a group
    """
    template_name = "user-register.html"
    form_class = forms.UserRegistrationForm
    
    def get_success_url(self, *args, **kwargs):
        model = self.get_object()
        self.request.session["user_id"] = model.id
        return reverse_lazy("users:add-to-group", kwargs={"username": model.username})


class AddToGroup(View):
    group_name = None
    model = django.contrib.auth.models.Group
    success_url = None

    def get_group_model(self):
        if self.group_name:
            return get_object_or_404(self.model, name=self.group_name)
        raise ImproperlyConfigured(f"AddToGroup needs either a definition of 'group_name'")
    
    def get_success_url(self):
        if self.success_url:
            return self.success_url
        raise ImproperlyConfigured(f"AddToGroup needs either a definition of 'success_url' or implimentaion of 'get_success_url'")

    def get_user_model(self):
        user_model = get_user_model()
        return get_object_or_404(user_model, id=self.request.session.get("user_id"))

    def get(self, request, *args, **kwargs):
        group = self.get_group_model()
        user = self.get_user_model()
        group.users.add(user)
        return redirect(self.get_success_url())


class AddToExampleGroup(AddtoGroup):
    group_name = "example"
    success_url = "users:login"

