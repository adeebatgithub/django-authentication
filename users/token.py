from django.contrib.auth.tokens import default_token_generator

from users.models import TokenModel


class TokenGenerator:
    model = TokenModel

    def generate_token(self, user):
        return default_token_generator.make_token(user)

    def create_token_model(self, user, token):
        model = self.model.objects.create(user=user, token=token)
        return model

    def get_token_model(self, token):
        return self.model.objects.filter(token=token).last()

    def make_token(self, user):
        token = self.generate_token(user)
        self.create_token_model(user, token)
        return token

    def delete_token(self, token=None, model=None):
        if model:
            model.delete()

        if token:
            model = self.get_token_model(token)
            model.delete()

    def is_valid(self, user, token):
        model = self.get_token_model(token)
        if model.user != user:
            return False

        if model.is_expired():
            return False

        return True

token_generator = TokenGenerator()