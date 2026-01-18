from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import Group
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponseForbidden
from django.views import generic

from users.apks.general.forms import UserRegistrationForm


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
    redirect_superuser_to_admin = True

    def get_group_and_url(self):
        if self.group_and_url:
            return self.group_and_url

    def get_redirect_url(self, *args, **kwargs):
        if self.redirect_superuser_to_admin and self.request.user.is_superuser:
            return "/admin"

        if self.get_group_and_url():
            for group, url in self.get_group_and_url().items():
                if self.request.user.is_member(group):
                    return url

        if self.pattern_name:
            return self.pattern_name

        if self.url:
            return self.url

        raise ImproperlyConfigured(
            "RedirectLoggedUser needs 'group_and_url' or 'pattern_name' or 'url'")


class BaseUserRegistrationView(generic.CreateView):
    model = get_user_model()
    form_class = UserRegistrationForm

    group_name = None
    group_model = Group

    def get_group_model(self):
        if self.group_name:
            group_name = self.group_name

        elif hasattr(settings, "DEFAULT_USER_GROUP_NAME"):
            group_name = settings.DEFAULT_USER_GROUP_NAME

        else:
            raise ImproperlyConfigured(
                f"{self.__class__.__name__} needs either a 'group_name' attribute "
                f"or DEFAULT_USER_GROUP_NAME setting"
            )

        group, created = self.group_model.objects.get_or_create(name=group_name)
        return group

    def form_valid(self, form):
        response = super().form_valid(form)

        group = self.get_group_model()
        if hasattr(form.instance, 'groups'):
            form.instance.groups.add(group)
        else:
            raise ImproperlyConfigured(
                f"Model {form.instance.__class__.__name__} doesn't have 'groups' attribute"
            )

        return response


class BaseUpdateUser(LoginRequiredMixin, generic.UpdateView):
    model = get_user_model()

    def get(self, request, *args, **kwargs):
        if request.user.username != self.kwargs.get("username"):
            return HttpResponseForbidden()
        return super().get(request, *args, **kwargs)
