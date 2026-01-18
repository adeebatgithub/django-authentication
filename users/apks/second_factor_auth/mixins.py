from braces.views._access import AccessMixin
from django.conf import settings
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.contrib.auth import get_user_model

from users.utilities.token.user_token import token_generator


class MultiFactorVerificationRequiredMixin(AccessMixin):

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return self.handle_no_permission(request)

        if not request.user.second_factor_verified:
            token = token_generator.generate_token(path="second-factor-verification").make_token(request.user)
            return redirect(reverse_lazy(settings.SECOND_FACTOR_VERIFICATION_URL, kwargs={"token": token}))

        if not self.request.session.get("2FA_STATUS"):
            user = get_user_model().objects.get(pk=request.user.pk)
            user.second_factor_verified = False
            user.save()
            return redirect(reverse_lazy(settings.LOGIN_REDIRECT_URL))

        return super(MultiFactorVerificationRequiredMixin, self).dispatch(request, *args, **kwargs)
