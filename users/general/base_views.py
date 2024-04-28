from django.contrib.auth import get_user_model
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import Group
from django.core.exceptions import ImproperlyConfigured
from django.shortcuts import get_object_or_404, redirect
from django.views import View, generic


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


class AddRole(View):
    """
    base implementation of adding a role to the user
    inherit and define 'role' and 'success_url'
    """
    role = None  # User.role
    success_url = None

    def get_role(self):
        if self.role:
            return self.role
        raise ImproperlyConfigured(f"{self.__class__.__name__} need a 'role'")

    def get_success_url(self):
        if self.success_url:
            return self.success_url
        raise ImproperlyConfigured(f"{self.__class__.__name__} needs 'success_url'")

    def get_user_object(self):
        return get_object_or_404(get_user_model(), id=self.request.session.get("user_id"))

    def get(self, request, *args, **kwargs):
        model = self.get_user_object()
        model.role = self.get_role()
        model.save()
        return redirect(self.get_success_url())


class AddToGroup(View):
    """
    base implementation of adding a user to a gruop
    inherit and define 'group_name' add 'success_url'
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
