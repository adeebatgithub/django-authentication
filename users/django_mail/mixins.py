from django.conf import settings
from django.core import mail
from django.core.exceptions import ImproperlyConfigured
from django.template.loader import render_to_string
from django.views.generic.edit import FormMixin as BaseFormMixin


class SendEmailMixin:
    from_email = None
    to_email = None
    # recipient_list = []
    email_subject = None
    message = None
    send_html_email = False
    email_template_name = None

    def get_to_email(self):
        return self.to_email

    # def get_recipient_email_list(self):
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

        raise ImproperlyConfigured \
            (f"{self.__class__.__name__} missing from email id, define 'from_email' or 'settings.EMAIL_HOST_USER:'")

    def get_email_template_name(self):
        if not self.email_template_name:
            raise ImproperlyConfigured \
                (f"{self.__class__.__name__} missing email template, define 'email_template_name'")
        return self.email_template_name

    def get_message(self):
        if self.send_html_email:
            print(self.get_email_context_data())
            return render_to_string(self.get_email_template_name(), self.get_email_context_data())

        if not self.message:
            raise ImproperlyConfigured(f"{self.__class__.__name__} missing content for sending email")
        return self.message

    def get_email_subject(self):
        if not self.email_subject:
            raise ImproperlyConfigured \
                (f"{self.__class__.__name__} need definition of 'email_subject' of implementation of 'get_email_subject'")
        return self.email_subject

    def send_text_mail(self):
        mail.send_mail(
            self.get_email_subject(),
            self.get_message(),
            self.get_from_email(),
            [self.get_to_email()],
        )

    def send_html_mail(self):
        email = mail.EmailMultiAlternatives(
            self.get_email_subject(),
            " ",
            self.get_from_email(),
            [self.get_to_email()]
        )
        email.attach_alternative(self.get_message(), "text/html")
        email.send()

    def send_mail(self):
        if self.send_html_email:
            self.send_html_mail()
        else:
            self.send_text_mail()


class FormMixin(BaseFormMixin):

    def post(self, *args, **kwargs):
        form = self.get_form()
        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)