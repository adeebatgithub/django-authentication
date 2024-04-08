from django.core import mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.core.exceptions import ImproperlyConfigured
from django.views.generic import TemplateView
from django import forms
from django.contrib.auth import get_user_model
from django.conf import settings
from django.shortcuts import redirect

# change all the email to mail

class SendEmailMixin:
    from_email = None
    to_email = None
    #recipient_list = []
    email_subject = None
    message = None
    send_html_email = False
    email_template_name = None

    def get_to_email(self):
        return self.to_email

    #def get_recipient_email_list(self):
    #    if self.to_email:
    #        return self.get_to_email()
#
    #    if not self.recipient_list:
    #        return self.recipient_list
#
    #    raise ImproperlyConfigured(f"{self.__class__.__name__} missing recipient emails, define 'recipient_list'")

    def get_from_email(self):
        if self.from_email:
            return self.from_email

        if settings.EMAIL_HOST_USER:
            return settings.EMAIL_HOST_USER

        raise ImproperlyConfigured(f"{self.__class__.__name__} missing from email id, define 'from_email' or 'settings.EMAIL_HOST_USER:'")

    def get_context_data(self):
        return {"email": self.get_to_email()}

    def get_email_template_name(self):
        if not self.email_template_name:
            raise ImproperlyConfigured(f"{self.__class__.__name__} missing email template, define 'email_template_name'")
        return self.email_template_name
    
    def get_message(self):
        if self.send_html_email:
            html_message = render_to_string(self.get_email_template_name(), self.get_context_data())
            return strip_tags(html_message)

        if not self.message:
            raise ImproperlyConfigured(f"{self.__class__.__name__} missing content for sending email")
        return self.message

    def get_email_subject(self):
        if not self.email_subject:
            raise ImproperlyConfigured(f"{self.__class__.__name__} need definition of 'email_subject' of implimentation of 'get_email_subject'")
        return self.email_subject
    
    def send_mail(self):
        mail.send_mail(
            self.get_email_subject(), 
            self.get_message(), 
            self.get_from_email(), 
            [self.get_to_email()],
        )


class EmailForm(forms.Form):
    email = forms.EmailField(widget=forms.TextInput(attrs={"autocomplete": "email", "placeholder": "Enter Your Email"}))


class SendEmailView(SendEmailMixin, TemplateView):
    template_name = None
    success_url = None
    form_class = EmailForm
    email_field_name = "email"

    def get_success_url(self):
        if not self.success_url:
            raise ImproperlyConfigured("{self.__class__.__name__} missing url to redirect after successful email send, define 'success_url'")
        return self.success_url

    def get_form(self):
        if self.request.POST:
            return self.form_class(self.request.POST)
        return self.form_class()

    def get_context_data(self, *args, **kwargs):
        context = TemplateView().get_context_data(*args, **kwargs)
        context.update({"form": self.get_form()})
        return context

    def form_valid(self, form):
        User = get_user_model()
        email = form.cleaned_data[self.email_field_name]
        if User.objects.filter(email=email).exists():
            self.request.session["email"] = email
            self.send_mail()
            return redirect(self.get_success_url())
        form.add_error("email", "This email is not registered")   
        return self.render_to_response({"form": form})

    def form_invalid(self, form):
        return self.render_to_response(self.get_context_data())

    def post(self, *args, **kwargs):
       form = self.get_form()
       if form.is_valid():
           return self.form_valid(form)
       else:
           return self.form_invalid(form)
