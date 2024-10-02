from django.contrib.auth import get_user_model
from django.contrib.auth import views as auth_views
from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse_lazy

from compact.token import TokenValidationMixin
from . import forms


class PasswordChangeView(LoginRequiredMixin, TokenValidationMixin, auth_views.PasswordChangeView):
    """
    change password
    """
    form_class = forms.ChangePasswordForm
    template_name = "password-change/user-password-change.html"

    def verify_email(self):
        model = get_user_model().objects.get(id=self.request.user.id)
        model.email_verified = True
        model.save()

    def get_success_url(self):
        if not self.request.user.email_verified:
            self.verify_email()

        return reverse_lazy("compact:profile", kwargs={"username": self.request.user.username})
