from django.conf import settings
from django.core import mail
from django.core.exceptions import ImproperlyConfigured
from django.template.loader import render_to_string

from users.utilities.mailing.payloads import EmailPayload

class EmailPayloadMixin:
    """
    A mixin for sending emil using django's email system (smtp)
    """
    from_email = None
    to_email = None
    email_subject = None
    message = None
    email_template_name = None

    def get_to_email(self):
        if self.to_email is None:
            raise ImproperlyConfigured(f"{self.__class__.__name__} missing from email id, define 'to_email'")
        return self.to_email

    def get_from_email(self):
        if self.from_email:
            return self.from_email

        if settings.EMAIL_HOST_USER:
            return settings.EMAIL_HOST_USER

        raise ImproperlyConfigured(
            f"{self.__class__.__name__} missing from email id, define 'from_email' or 'settings.EMAIL_HOST_USER'")

    def get_email_template_name(self):
        if not self.email_template_name:
            raise ImproperlyConfigured(
                f"{self.__class__.__name__} missing email template, define 'email_template_name'")
        return self.email_template_name

    def get_email_context_data(self):
        pass

    def get_message(self):
        if not self.message:
            raise ImproperlyConfigured(f"{self.__class__.__name__} missing content for sending email")
        return self.message

    def render_email_template(self):
        if not self.email_template_name:
            raise ImproperlyConfigured(f"{self.__class__.__name__} missing content for sending email")
        return render_to_string(self.get_email_template_name(), self.get_email_context_data())

    def get_email_subject(self):
        if not self.email_subject:
            raise ImproperlyConfigured(
                f"{self.__class__.__name__} need definition of 'email_subject' of implementation of 'get_email_subject'"
            )
        return self.email_subject

    def build_email_payload(self) -> EmailPayload:
        if self.email_template_name:
            return EmailPayload(
                subject=self.get_email_subject(),
                from_email=self.get_from_email(),
                to=[self.get_to_email()],
                html=self.render_email_template(),
            )

        return EmailPayload(
            subject=self.get_email_subject(),
            from_email=self.get_from_email(),
            to=[self.get_to_email()],
            text=self.get_message(),
        )


class SendEmailMixin(EmailPayloadMixin):

    def send_mail(self):
        payload = self.build_email_payload()
        if payload.html:
            email = mail.EmailMultiAlternatives(
                payload.subject,
                payload.text,
                payload.from_email,
                payload.to,
            )
            email.attach_alternative(payload.html, "text/html")
            email.send()
        else:
            mail.send_mail(
                payload.subject,
                payload.text,
                payload.from_email,
                payload.to,
            )
