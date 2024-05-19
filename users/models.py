import datetime

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ImproperlyConfigured
from django.db import models
from django.utils import timezone


class User(AbstractUser):
    # roles
    # role name = index number
    # CUSTOMER = 1
    # STAFF = 2
    EXAMPLE_ROLE = 1
    STAFF = 2
    ROLES = (
        # (CUSTOMER, "customer")
        (STAFF, "staff"),
        (EXAMPLE_ROLE, "example role"),
    )

    role = models.PositiveSmallIntegerField(choices=ROLES, null=True, blank=True)
    email_verified = models.BooleanField(default=False, null=True)

    def is_email_verified(self):
        return self.email_verified

    def has_role(self, role):
        return self.role == role

    def get_role(self):
        role = [r for r in self.ROLES if r[0] == self.role][0]
        return role


class OTPModel(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=settings.OTP_LENGTH, null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True)
    expires = models.DateTimeField(null=True, blank=True)

    def is_expired(self):
        return timezone.now() > self.expires

    def get_otp_expiry(self):
        if settings.OTP_EXPIRY:
            return settings.OTP_EXPIRY
        return {"minutes": 30}

    def save(self, *args, **kwargs):
        if not self.pk:
            self.expires = timezone.now() + datetime.timedelta(**self.get_otp_expiry())
        super(OTPModel, self).save(*args, **kwargs)

    def __str__(self):
        return f"{self.otp} | {self.is_expired()}"


class TokenModel(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=255)
    created = models.DateTimeField(auto_now_add=True)
    expires = models.DateTimeField(null=True, blank=True)

    def is_expired(self):
        return timezone.now() > self.expires

    def get_token_expiry(self):
        if settings.TOKEN_EXPIRY:
            return settings.TOKEN_EXPIRY
        return {"minutes": 10}

    def save(self, *args, **kwargs):
        if not self.pk:
            self.expires = timezone.now() + datetime.timedelta(**self.get_token_expiry())
        super(TokenModel, self).save(*args, **kwargs)

    def __str__(self):
        return f"{self.id} | {self.token} | {self.expires} | {self.is_expired()}"
