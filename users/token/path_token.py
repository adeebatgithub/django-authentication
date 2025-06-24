from django.core import signing
from django.shortcuts import redirect
from django.urls import reverse_lazy


class PathTokenGenerator:

    def generate_token(self, session_id, path):
        token = signing.dumps({"session_id": session_id, "path": path})
        return token


path_token_generator = PathTokenGenerator()


class PathTokenValidationMixin:
    """
    path is verified using the session id and path
    """
    pre_path = None
    token_invalid_redirect_url = reverse_lazy("users:redirect-user")

    def token_invalid(self):
        # message
        return redirect(self.token_invalid_redirect_url)

    def dispatch(self, request, *args, **kwargs):
        if request.method == "GET":
            params = signing.loads(self.kwargs.get("token"))
            if params.get("path") != self.pre_path or request.session.session_key != params.get("session_id"):
                print("path token invalid")
                print(f"path: {params.get("path")} -> {self.pre_path}")
                print(f"path: {params.get("session_id")} -> {request.session.session_key}")
                return self.token_invalid()

        return super().dispatch(request, *args, **kwargs)
