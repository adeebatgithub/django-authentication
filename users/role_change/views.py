from braces.views import LoginRequiredMixin, SuperuserRequiredMixin
from django.conf import settings
from django.contrib.auth import get_user_model
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.views import generic, View

from users.django_mail.mixins import SendEmailMixin
from users.django_mail.views import SendEmailView
from users.token.user_token import TokenValidationMixin
from .base_views import BaseRoleChangeView
from ..utils import generate_uidb64_url


class RoleChangeRequestMail(LoginRequiredMixin, SendEmailView):
    """
    Send an email to the admin requesting role change (by user)
    """
    to_email = settings.EMAIL_HOST_USER
    email_subject = "Role Change Request"
    send_html_email = True
    email_template_name = "users/role/role-change-mail.html"
    success_url = reverse_lazy("users:role-send-mail-done")

    def get_success_url(self):
        return self.success_url

    def get_from_email(self):
        return self.request.user.email

    def get_email_context_data(self):
        url = reverse_lazy(
            "users:role-change-confirm",
            kwargs={"username": self.request.user.username, "role": self.kwargs.get("role")})
        absolute_url = self.request.build_absolute_uri(url)
        return {
            "username": self.request.user.username,
            "email": self.request.user.email,
            "current_role": self.request.user.get_role_display(),
            "role": self.kwargs.get("role"),
            "url": absolute_url,
        }


class RoleChangeRequestSendDone(LoginRequiredMixin, generic.TemplateView):
    """
    notifying user
    """
    template_name = "users/role/send-done.html"

    def get_context_data(self, **kwargs):
        return {"message": "An Email is sent to the admin"}


class RoleChangeConfirm(SuperuserRequiredMixin, generic.TemplateView):
    """
    admin confirmed the request from the mail
    """
    template_name = "users/role/role-change-confirm.html"

    def get_user(self):
        return get_user_model().objects.get(username=self.kwargs.get("username"))

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.get_user()
        self.kwargs["user"] = user
        accept_url = generate_uidb64_url(pattern_name="users:role-change-accept", user=user)
        decline_url = reverse_lazy("users:role-change-decline-mail")
        self.request.session["USER_EMAIL"] = user.email
        self.request.session["USER_NAME"] = user.username
        self.request.session["ROLE"] = self.kwargs.get("role")
        context.update({
            "username": user.username,
            "email": user.email,
            "role": self.kwargs.get("role"),
            "accept_url": accept_url,
            "decline_url": decline_url,
        })
        return context


class RoleChangeView(TokenValidationMixin, BaseRoleChangeView):

    def get_role_name(self):
        return getattr(get_user_model(), self.request.session["ROLE"])

    def get_group_name(self):
        return self.request.session["ROLE"].lower()

    def get_user(self):
        return self.get_user_model()

    def get_success_url(self):
        return reverse_lazy("users:role-change-accept-mail")


class RoleChangeDoneMail(SendEmailView):
    email_subject = "Role Change Done"
    send_html_email = True
    email_template_name = "users/role/role-change-done-mail.html"

    def get_success_url(self):
        return reverse_lazy("users:role-change-done")

    def get_to_email(self):
        return self.request.session.pop("USER_EMAIL")

    def get_email_context_data(self):
        return {"message": "your role change request has been verified and changed successfully"}


class RoleChangeDone(generic.TemplateView):
    template_name = "users/role/role-change-done.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update({
            "username": self.request.session.pop("USER_NAME"),
            "role": self.request.session.pop("ROLE"),
            "status": "accepted",
        })
        return context


class RoleChangeFailMail(LoginRequiredMixin, SendEmailMixin, View):
    email_subject = "Role Change Failed"
    send_html_email = True
    email_template_name = "users/role/role-change-done-mail.html"
    success_url = reverse_lazy("users:role-change-fail")

    def get_success_url(self):
        return self.success_url

    def get_to_email(self):
        return self.request.session.pop("USER_EMAIL")

    def get_email_context_data(self):
        return {"message": "your role change request has been declined by the admin"}

    def get(self, request, *args, **kwargs):
        self.send_mail()
        return redirect(self.get_success_url())


class RoleChangeDeclined(generic.TemplateView):
    template_name = "users/role/role-change-done.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update({
            "username": self.request.session.pop("USER_NAME"),
            "role": self.request.session.pop("ROLE"),
            "status": "declined",
        })
        return context
