from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import Group
from django.core.exceptions import ImproperlyConfigured
from django.shortcuts import redirect
from django.urls import reverse_lazy, resolve
from django.views import generic

from users.general.forms import UserRegistrationForm


class RedirectUserView(LoginRequiredMixin, generic.RedirectView):
    """
    users are redirected based on role or group
    to redirect users based on group define 'group_and_url'
    to redirect users based on role define 'role_and_url'
    to redirect all users to same url or to redirect users who are not in any group, define 'pattern_name'
    """
    group_and_url = {
        # group name: redirect url
        # customer: reverse_lazy("customer-home")
    }
    role_and_url = {
        # role name: redirect url
        # User.staff: reverse_lazy("staff-home")
    }
    pattern_name = None
    redirect_superuser_to_admin = True

    def get_group_and_url(self):
        if self.group_and_url:
            return self.group_and_url

    def get_role_and_url(self):
        if self.role_and_url:
            return self.role_and_url

    def get_pattern_name(self):
        if self.pattern_name:
            return self.pattern_name

    @staticmethod
    def is_member(user, group):
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


class AddRoleMixin:
    role = None  # User.role
    role_field = "role"

    def get_role(self):
        if self.role:
            return self.role

        if hasattr(settings, "DEFAULT_USER_ROLE"):
            return getattr(get_user_model(), settings.DEFAULT_USER_ROLE)

        raise ImproperlyConfigured(f"{self.__class__.__name__} need a 'role'")

    def form_valid(self, form):
        role = self.get_role()
        setattr(form.instance, self.role_field, role)
        return super().form_valid(form)


class AddToGroupMixin:
    group_name = None
    model = Group

    def get_group_model(self):
        group_name = None

        if self.group_name:
            group_name = self.group_name
        elif hasattr(settings, "DEFAULT_USER_GROUP_NAME"):
            group_name = settings.DEFAULT_USER_GROUP_NAME  # Fixed: was using self.group_name
        else:
            raise ImproperlyConfigured(
                f"{self.__class__.__name__} needs either a 'group_name' attribute "
                f"or DEFAULT_USER_GROUP_NAME setting"
            )

        group, created = self.model.objects.get_or_create(name=group_name)
        return group

    def form_valid(self, form):
        response = super().form_valid(form)  # Save the object first

        # Add user to group after object is saved
        group = self.get_group_model()
        if hasattr(form.instance, 'groups'):  # Check if instance has groups (User model)
            form.instance.groups.add(group)
        else:
            # Handle case where it's not a User model
            raise ImproperlyConfigured(
                f"Model {form.instance.__class__.__name__} doesn't have 'groups' attribute"
            )

        return response


class BaseUserRegistrationView(generic.CreateView):
    model = get_user_model()
    form_class = UserRegistrationForm

    role = None  # User.role
    role_field = "role"

    group_name = None
    group_model = Group

    def get_role(self):
        if self.role:
            return self.role

        if hasattr(settings, "DEFAULT_USER_ROLE"):
            return getattr(get_user_model(), settings.DEFAULT_USER_ROLE)

        raise ImproperlyConfigured(f"{self.__class__.__name__} need a 'role'")

    def get_group_model(self):
        if self.group_name:
            group_name = self.group_name
        elif hasattr(settings, "DEFAULT_USER_GROUP_NAME"):
            group_name = settings.DEFAULT_USER_GROUP_NAME  # Fixed: was using self.group_name
        else:
            raise ImproperlyConfigured(
                f"{self.__class__.__name__} needs either a 'group_name' attribute "
                f"or DEFAULT_USER_GROUP_NAME setting"
            )

        group, created = self.group_model.objects.get_or_create(name=group_name)
        return group

    def form_valid(self, form):
        role = self.get_role()
        setattr(form.instance, self.role_field, role)

        response = super().form_valid(form)  # Save the object first

        # Add user to group after object is saved
        group = self.get_group_model()
        if hasattr(form.instance, 'groups'):  # Check if instance has groups (User model)
            form.instance.groups.add(group)
        else:
            # Handle case where it's not a User model
            raise ImproperlyConfigured(
                f"Model {form.instance.__class__.__name__} doesn't have 'groups' attribute"
            )

        return response


class UpdateUser(LoginRequiredMixin, generic.UpdateView):
    model = get_user_model()
    template_name = "users/general/update.html"
    slug_field = "username"
    slug_url_kwarg = "username"
    title = None

    def get_success_url(self):
        return reverse_lazy("users:profile", kwargs={"username": self.object.username})

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update({
            "title": self.title
        })
        return context

    def get(self, request, *args, **kwargs):
        if request.user.username != self.kwargs.get("username"):
            pattern = f"users:{resolve(request.path).url_name}"
            return redirect(reverse_lazy(pattern, kwargs={"username": self.request.user.username}))
        return super().get(request, *args, **kwargs)
