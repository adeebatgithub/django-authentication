from django.shortcuts import redirect
from django.urls import reverse_lazy


class AccessRequiredMixin:

    def dispatch(self, request, *args, **kwargs):
        if not self.request.SESSION.get('access'):
            return redirect(reverse_lazy("compact:profile-redirect"))
        super().dispatch(request, *args, **kwargs)
