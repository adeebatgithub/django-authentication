from django.contrib.auth import get_user_model
from django.http import JsonResponse
from django.views import View


class UserNameValidator(View):
    model = get_user_model()

    def get(self, request, username):
        if self.model.objects.filter(username=username).exists():
            return JsonResponse({'exists': True})
        return JsonResponse({'exists': False})


class EmailValidator(View):
    model = get_user_model()

    def get(self, request, email):
        if self.model.objects.filter(email=email).exists():
            return JsonResponse({'exists': True})
        return JsonResponse({'exists': False})
