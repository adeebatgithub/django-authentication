from braces.views import LoginRequiredMixin
from django.contrib.auth import logout
from django.urls import reverse_lazy
from django.views.generic import FormView

from .forms import PasswordSetForm


class SetPasswordView(LoginRequiredMixin, FormView):
    template_name = 'users/set-password/set_password.html'
    form_class = PasswordSetForm

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.request.user
        return kwargs

    def form_valid(self, form):
        form.save()
        return super().form_valid(form)

    def get_success_url(self):
        logout(self.request)
        return reverse_lazy('users:redirect-user')
