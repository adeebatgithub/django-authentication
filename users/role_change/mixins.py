

class SuperUserRequiredMixin:

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_superuser:
            super().dispatch(request, *args, **kwargs)
        raise PermissionError("You do not have permission")