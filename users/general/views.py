from django.contrib.auth import views as auth_views, get_user_model
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core import signing
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.views import generic

from users.django_mail import views as mail_views
from users.token_generators.user_token import PathTokenValidationMixin, token_generator
from . import forms, base_views


class RedirectUserView(base_views.RedirectUserView):
    """
    Users Redirect View, redirect logged-in user
    """

    def get_pattern_name(self):
        return reverse_lazy("users:profile", kwargs={"username": self.request.user.username})


class ProfileView(LoginRequiredMixin, generic.TemplateView):
    """
    user profile page
    """
    template_name = "users/general/profile.html"

    def get(self, request, *args, **kwargs):
        if kwargs.get("username") != request.user.username:
            return redirect(reverse_lazy("users:profile", kwargs={"username": request.user.username}))
        return super().get(request, kwargs.get("username"))


class LoginView(auth_views.LoginView):
    """
    Users Login View

    redirect user to url specified in settings.LOGIN_REDIRECT_URL
    set settings.LOGIN_REDIRECT_URL to 'users:redirect-logged-user'
    to redirect user based on the group or role
    """
    template_name = "users/general/login.html"
    form_class = forms.UserLoginForm
    redirect_authenticated_user = True
    pattern_name = "users:redirect-user"

    def get_redirect_url(self):
        return reverse_lazy(self.pattern_name)

    def form_valid(self, form):
        form.reset_login_attempts()
        self.request.session.cycle_key()
        return super().form_valid(form)

    def form_invalid(self, form):
        if "account_locked" in form.error_messages:
            return redirect("users:get-email-lock")
        return super().form_invalid(form)


class LogoutView(auth_views.LogoutView):
    """
    Users Logout View

    redirect user to login page
    """
    next_page = "users:login"
    http_method_names = ["get", "post", "put"]
    success_url = reverse_lazy("users:login")

    def get_success_url(self):
        return self.success_url

    def get(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)


class RegisterView(generic.CreateView):
    """
    User creation/registration view

    regular user is created and redirected to add the user in to a group
    """
    model = get_user_model()
    template_name = "users/general/register.html"
    form_class = forms.UserRegistrationForm
    success_url = reverse_lazy("users:add-example-role")

    def get_success_url(self, *args, **kwargs):
        self.request.session["user_id"] = self.object.id
        return self.success_url


class AddExampleRole(base_views.AddRole):
    """
    give users the specified role     is specified in settings.DEFAULT_USER_ROLE
    """
    success_url = reverse_lazy("users:add-to-example-group")


class AddToExampleGroup(base_views.AddToGroup):
    """
    add users to the specified group,
    group name is specified in settings.DEFAULT_USER_GROUP_NAME
    """
    success_url = reverse_lazy("users:redirect-user")


class DeleteUserSendMail(LoginRequiredMixin, mail_views.SendEmailView):
    """
    send email to confirm the delete request
    """
    email_subject = "Delete User Request"
    send_html_email = True
    email_template_name = "general/deletion-mail.html"
    success_url = reverse_lazy("users:delete-mail-done")

    def get_to_email(self):
        return self.request.user.email

    def get_email_context_data(self):
        url = reverse_lazy("users:delete-user-confirm")
        uri = self.request.build_absolute_uri(url)
        return {
            "url": uri,
            "user": self.request.user,
        }


class MailSendDoneView(LoginRequiredMixin, generic.TemplateView):
    """
    render a template after successfully sending email with success message
    """
    template_name = "users/mail/send-done.html"

    def get_context_data(self, *args, **kwargs):
        email = self.request.user.email
        context = super().get_context_data()
        context.update({"message": f"An Email is sent to your email id - {email} with instructions"})
        return context


class DeleteUserConfirmation(LoginRequiredMixin, generic.TemplateView):
    """
    confirm user delete or dont
    """
    template_name = "users/general/delete-confirm.html"

    def get_context_data(self, **kwargs):
        token = token_generator.generate_token(user_id=self.request.user.id,
                                               path="delete-user-confirmation").make_token(self.request.user.id)
        delete_url = reverse_lazy("users:delete-user", kwargs={"token": token})
        decline_url = reverse_lazy("users:delete-user-decline", kwargs={"token": token})
        print(delete_url, decline_url)
        context = super().get_context_data(**kwargs)
        context.update({
            "delete_url": delete_url,
            "decline_url": decline_url
        })
        return context


class DeleteUseDecline(LoginRequiredMixin, PathTokenValidationMixin, generic.RedirectView):
    """
    redirect user if delete confirmation declined
    """
    pre_path = "delete-user-confirmation"
    url = reverse_lazy("users:redirect-user")


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


class ChangeUsername(base_views.UpdateUser):
    form_class = forms.ChangeUsernameForm
    title = "Username"


class ChangeFullname(base_views.UpdateUser):
    form_class = forms.ChangeFullnameForm
    title = "Fullname"


class ChangeEmail(base_views.UpdateUser):
    form_class = forms.ChangeEmailForm
    title = "Email"

    def change_email_status(self):
        model = self.object
        model.email_verified = False
        model.save()
        return model

    def get_success_url(self):
        self.change_email_status()
        return super().get_success_url()
