from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.views import generic

from users.apks.second_factor_auth.mixins import MultiFactorVerificationRequiredMixin


class ProfileView(LoginRequiredMixin, MultiFactorVerificationRequiredMixin, generic.TemplateView):
    """
    user profile page
    """
    template_name = "users/general/profile.html"

    def get(self, request, *args, **kwargs):
        if kwargs.get("username") != request.user.username:
            return redirect(reverse_lazy("users:profile", kwargs={"username": request.user.username}))
        return super().get(request, *args, **kwargs)