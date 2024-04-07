from django.contrib.auth import views as auth_views
from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse_lazy
from django.views import generic, View
from django.core.exceptions import ImproperlyConfigured
from django.shortcuts import get_object_or_404, redirect
from django.conf import settings
from django.contrib.auth.models import Group
from django.contrib.auth import get_user_model

from . import forms


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
        #group name: redirect url
        #customer: reverse_lazy("customer-home")
    }
    role_and_url = {
        #role name: redirect url
        #User.staff: reverse_lazy("staff-home")
    }
    pattern_name = reverse_lazy("users:profile")

    def get_group_and_url(self):
        #if self.group_and_url:
        #    return self.group_and_url
        return {"example": reverse_lazy("users:profile", kwargs={"username": self.request.user.username})}

    def get_role_and_url(self):
        if self.role_and_url:
            return self.role_and_url

    def get_pattern_name(self):
        #if self.pattern_name:
        #    return self.pattern_name
        return reverse_lazy("users:profile", kwargs={"username": self.request.user.username})

    def is_member(self, user, group):
        return user.groups.filter(name=group).exists()
    
    def get_redirect_url(self, *args, **kwargs):
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

        raise ImproperlyConfigured("RedirectLoggedUser needs dict of 'group_and_url' or 'role_and_url' or 'pattern_name'")


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
    success_url = reverse_lazy("users:add-to-example-group")
    
    def get_success_url(self, *args, **kwargs):
        self.request.session["user_id"] = self.object.id
        return self.success_url


class AddToGroup(View):
    """
    base implimentation of adding a user to a gruop
    inherit and define 'group_name' add the user to the group
    """
    group_name = None
    model = Group
    success_url = None

    def get_group_model(self):
        if self.group_name:
            return get_object_or_404(self.model, name=self.group_name)
        raise ImproperlyConfigured(f"AddToGroup needs either a definition of 'group_name'")
    
    def get_success_url(self):
        if self.success_url:
            return self.success_url
        return reverse("users:login")

    def get_user_model(self, **kwargs):
        user_model = get_user_model()
        return get_object_or_404(user_model, **kwargs)

    def get(self, request, *args, **kwargs):
        group = self.get_group_model()
        user_id = request.session.pop("user_id")
        user = self.get_user_model(id=user_id)
        user.groups.add(group)
        return redirect(self.get_success_url())


class AddToExampleGroup(AddToGroup):
    group_name = "example"

