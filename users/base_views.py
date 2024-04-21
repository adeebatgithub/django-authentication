from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import ImproperlyConfigured
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse_lazy
from django.views import View


class AddRole(View):
    """
    base implementation of adding a role to the user
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
    base implementation of adding a user to a gruop
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


class RoleChangeView(View):
    role_name = None
    success_url = reverse_lazt("users:role-change-done")

    def get_role_name(self):
        if self.role_name:
            return self.role_name
        raise ImproperlyConfiguered(f"{self.__class__.__name__} missing role_name")

    def get_user_model(self):
        user_id = urlsafe_base64_decode(self.kwargs.get("uidb64"))
        return get_object_or_404(get_user_model(), id=user_id)

    def get_success_url(self):
        if self.success_url:
            return self.success_url
        raise ImproperlyConfiguered(f"{self.__class__.__name__} missing success_url")

    def set_role(self, user):
        user.role = self.get_role_name()
        user.save()

    def add_to_group(self, user):
        user.groups.add(self.role_name)

    def get(self, request, **kwargs):
        user = self.get_user_model()
        self.set_role(user)
        self.add_to_group(users)                                request.session["USER_NAME"] = user.username            request.session["ROLE"] = kwargs.get("role")
        return redirect(self.get_success_url())
