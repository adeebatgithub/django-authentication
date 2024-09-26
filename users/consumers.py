import json
from channels.generic.websocket import WebsocketConsumer
from django.contrib.auth import get_user_model


class ValidatorConsumer(WebsocketConsumer):

    def connect(self):
        self.accept()

    def disconnect(self, code):
        self.close()

    def is_exist(self, model, selector):
        return model.objects.filter(**selector).exists()

    def receive(self, text_data=None):
        data = json.loads(text_data)
        message = False
        if self.is_exist(get_user_model(), data):
            message = True
        self.send(text_data=json.dumps({"message": message}))
