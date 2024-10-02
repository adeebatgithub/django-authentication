from django.core.exceptions import ImproperlyConfigured
from django.shortcuts import redirect
from django.views import generic, View

from users.mixins import FormMixin
from .forms import EmailForm
from .mixins import SendEmailMixin


class GetEmailView(FormMixin, generic.TemplateView):
    template_name = None
    form_class = EmailForm

    def form_valid(self, form):
        self.request.session['USER_EMAIL'] = form.cleaned_data['email']
        return redirect(self.get_success_url())


class SendEmailView(SendEmailMixin, View):
    """
    View to send email using django's smtp system
    """
    success_url = None

    def get_success_url(self):
        if self.success_url:
            return self.success_url
        raise ImproperlyConfigured(
            f"{self.__class__.__name__} missing 'success_url' attribute, define 'success_url' attribute or define "
            f"'get_success_url' method")

    def get(self, request, *args, **kwargs):
        self.send_mail()
        return redirect(self.get_success_url())
