from braces.views._access import AccessMixin
from django.conf import settings
from django.shortcuts import redirect
from django.urls import reverse_lazy

from users.token_generators.user_token import token_generator


class MultiFactorVerificationRequiredMixin(AccessMixin):

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return self.handle_no_permission(request)

        if not request.user.second_factor_verified:
            token = token_generator.generate_token(path="second-factor-verification").make_token(request.user)
            return redirect(reverse_lazy(settings.SECOND_FACTOR_VERIFICATION_URL, kwargs={"token": token}))
        return super(MultiFactorVerificationRequiredMixin, self).dispatch(request, *args, **kwargs)
