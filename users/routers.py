from django.urls import path

from . import consumers


websocket_urlpatterns = [
    path('ws/validator/', consumers.ValidatorConsumer.as_asgi()),
]