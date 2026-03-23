from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend

import users.models
from users.utils import get_if_exists


class UsernameAuthBackend(ModelBackend):
    def authenticate(self, request, **kwargs):
        user: users.models.User = get_if_exists(get_user_model(), username=kwargs.get("username"))
        if not user:
            return None
        if not user.check_password(kwargs.get("password")):
            return None
        return user

    def get_user(self, user_id):
        user = get_if_exists(get_user_model(), id=user_id)
        if not user:
            return None
        return user


class EmailAuthBackend(ModelBackend):
    def authenticate(self, request, **kwargs):
        user: users.models.User = get_if_exists(get_user_model(), email=kwargs.get("username"))
        if not user:
            return None
        if not user.check_password(kwargs.get("password")):
            return None
        return user

    def get_user(self, user_id):
        user = get_if_exists(get_user_model(), id=user_id)
        if not user:
            return None
        return user


class UsernameOrEmailAuthBackend(ModelBackend):
    def authenticate(self, request, **kwargs):
        user = get_if_exists(get_user_model(), username=kwargs.get("username"))
        if not user:
            user = get_if_exists(get_user_model(), email=kwargs.get("username"))
            if not user:
                return None

        if not user.check_password(kwargs.get("password")):
            return None
        return user

    def get_user(self, user_id):
        user = get_if_exists(get_user_model(), id=user_id)
        if not user:
            return None
        return user
