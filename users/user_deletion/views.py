from braces.views import LoginRequiredMixin
from django.contrib.auth import get_user_model
from django.core import signing
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.views import generic

from users.django_mail import views as mail_views
from users.token.user_token import PathTokenValidationMixin, token_generator


class DeleteUserSendMail(LoginRequiredMixin, mail_views.SendEmailView):
    """
    send email to confirm the delete request
    """
    email_subject = "Delete User Request"
    send_html_email = True
    email_template_name = "users/user-deletion/mail.html"
    success_url = reverse_lazy("users:delete-mail-done")

    def get_to_email(self):
        return self.request.user.email

    def get_email_context_data(self):
        token = token_generator.generate_token(user_id=self.request.user.id,
                                                    path="user-deletion-mail").make_token(self.request.user)
        url = reverse_lazy("users:delete-user-confirm", kwargs={"token": token})
        uri = self.request.build_absolute_uri(url)
        return {
            "url": uri,
            "user": self.request.user,
        }


class MailSendDoneView(LoginRequiredMixin, generic.TemplateView):
    """
    render a template after successfully sending email with success message
    """
    template_name = "users/user-deletion/send-done.html"


class DeleteUserConfirmation(LoginRequiredMixin, PathTokenValidationMixin, generic.TemplateView):
    """
    confirm user delete or dont
    """
    pre_path = "user-deletion-mail"
    template_name = "users/user-deletion/delete-confirm.html"

    def get_context_data(self, **kwargs):
        token = token_generator.generate_token(user_id=self.request.user.id,
                                                    path="delete-user-confirmation").make_token(self.request.user)
        delete_url = reverse_lazy("users:delete-user", kwargs={"token": token})
        decline_url = reverse_lazy("users:delete-user-decline", kwargs={"token": token})
        context = super().get_context_data(**kwargs)
        context.update({
            "accept_url": delete_url,
            "decline_url": decline_url
        })
        return context


class DeleteUser(LoginRequiredMixin, PathTokenValidationMixin, generic.DeleteView):
    """
    delete user
    """
    pre_path = "delete-user-confirmation"
    model = get_user_model()
    success_url = reverse_lazy("users:redirect-user")

    def get_object(self, queryset=None):
        token_params = signing.loads(self.kwargs.get("token"))
        if self.request.user.id != token_params["user_id"]:
            return redirect(reverse_lazy("users:redirect-user"))
        return get_user_model().objects.get(id=token_params["user_id"])

    def get(self, request, *args, **kwargs):
        return super().delete(request, *args, **kwargs)


class DeleteUseDecline(LoginRequiredMixin, PathTokenValidationMixin, generic.RedirectView):
    """
    redirect user if delete confirmation declined
    """
    pre_path = "delete-user-confirmation"
    url = reverse_lazy("users:redirect-user")
