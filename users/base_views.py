from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import ImproperlyConfigured
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse_lazy
from django.utils.http import urlsafe_base64_decode
from django.views import View



class RoleChangeView(View):
    role_name = None
    group_name = None
    success_url = None

    def get_role_name(self):
        if self.role_name:
            return self.role_name
        raise ImproperlyConfigured(f"{self.__class__.__name__} missing role_name")

    def get_group_name(self):
        if self.group_name:
            return self.group_name
        raise ImproperlyConfigured(f"{self.__class__.__name__} missing group_name")

    def get_user_model(self):
        user_id = urlsafe_base64_decode(self.kwargs.get("uidb64"))
        return get_object_or_404(get_user_model(), id=user_id)

    def get_success_url(self):
        if self.success_url:
            return self.success_url
        raise ImproperlyConfigured(f"{self.__class__.__name__} missing success_url")

    def set_role(self, user):
        user.role = self.get_role_name()
        user.save()

    def add_to_group(self, user):
        previous = user.groups.all()
        for group in previous:
            user.groups.remove(group)
        group = get_object_or_404(Group, name=self.get_group_name())
        user.groups.add(group)

    def get(self, request, **kwargs):
        user = self.get_user_model()
        self.set_role(user)
        self.add_to_group(user)
        request.session["USER_NAME"] = user.username
        request.session["USER_EMAIL"] = user.email
        request.session["ROLE"] = self.get_role_name()
        return redirect(self.get_success_url())
