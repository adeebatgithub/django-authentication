from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse_lazy
from django.utils.http import urlsafe_base64_decode
from django.views import generic, View

from users.django_mail.mixins import SendEmailMixin
from users.django_mail.views import generate_uidb64_url, SendEmailView
from .base_views import RoleChangeView
from .mixins import SuperUserRequiredMixin


class RoleSendChangeMail(LoginRequiredMixin, SendEmailView):
    to_email = settings.EMAIL_HOST_USER
    email_subject = "Role Change Request"
    send_html_email = True
    email_template_name = "role/user-role-change-mail.html"
    success_url = reverse_lazy("users:role-send-mail-done")

    def get_success_url(self):
        return self.success_url

    def get_from_email(self):
        return self.request.user.email

    def get_email_context_data(self):
        url = reverse_lazy("users:role-change-confirm", kwargs={"username": self.request.user.username, "role": self.kwargs.get("role")})
        absolute_url = self.request.build_absolute_uri(url)
        return {
            "username": self.request.user.username,
            "email": self.request.user.email,
            "current_role": self.request.user.role,
            "role": self.kwargs.get("role"),
            "url": absolute_url,
        }


class RoleChangeMailSendDone(LoginRequiredMixin, generic.TemplateView):
    template_name = "role/user-role-chane-mail-send-done.html"


class RoleChangeConfirm(SuperUserRequiredMixin, generic.TemplateView):
    template_name = "role/user-role-change-confirm.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        accept_url = generate_uidb64_url(
            pattern_name="users:role-change",
            user=self.request.user,
        )
        decline_url = generate_uidb64_url(
            pattern_name="users:role-change-fail",
            user=self.request.user,
            role=self.request.session.get("ROLE")
        )
        context.update({
            "username": self.request.session.get("USER_NAME"),
            "email": self.request.session.get("USER_EMAIL"),
            "role": self.request.session.get("ROLE"),
            "accept_url": accept_url,
            "decline_url": decline_url,
        })
        return context


class RoleChangeDone(generic.TemplateView):
    template_name = "role/user-role-change-done.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update({
            "username": self.request.session.pop("USER_NAME"),
            "role": self.request.session.pop("ROLE"),
            "status": "accepted",
        })
        return context


class RoleChangeDoneMail(SendEmailView):
    email_subject = "Role Change Done"
    send_html_email = True
    email_template_name = "role/user-role-change-done-mail.html"
    success_url = reverse_lazy("users:role-change-done")

    def get_success_url(self):
        return self.success_url

    def get_to_email(self):
        return self.request.session.pop("USER_EMAIL")

    def get_email_context_data(self):
        return {"message": "your role change request has been verified and changed successfully"}


class RoleChangeDeclined(generic.TemplateView):
    template_name = "role/user-role-change-done.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update({
            "username": self.request.session.pop("USER_NAME"),
            "role": self.request.session.pop("ROLE"),
            "status": "declined",
        })
        return context


class RoleChangeDecline(generic.RedirectView):

    def get_redirect_url(self, *args, **kwargs):
        user_id = urlsafe_base64_decode(self.kwargs.get("uidb64"))
        user = get_object_or_404(get_user_model(), id=user_id)
        self.request.session["USER_NAME"] = user.username
        self.request.session["USER_EMAIL"] = user.email
        self.request.session["ROLE"] = self.kwargs.get("role")
        return reverse_lazy("users:change-role-fail-mail")


class RoleChangeFailMail(LoginRequiredMixin, SendEmailMixin, View):
    email_subject = "Role Change Failed"
    send_html_email = True
    email_template_name = "role/user-role-change-done-mail.html"
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


class RoleChangeToStaff(RoleChangeView):
    role_name = get_user_model().STAFF
    group_name = "staff"
    success_url = reverse_lazy("users:change-role-done-mail")
