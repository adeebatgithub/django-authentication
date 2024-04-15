from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings
from django.utils import timezone
import datetime


class User(AbstractUser):
    # roles
    # role name = index number
    # CUSTOMER = 1
    # STAFF = 2
    EXAMPLE_ROLE = 1
    ROLES = (
        # (CUSTOMER, "customer")
        # (STAFF, "staff")
        (EXAMPLE_ROLE, "example role"),
    )
    
    role = models.PositiveSmallIntegerField(choices=ROLES, null=True, blank=True)


class OTPModel(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=settings.OTP_LENGTH, null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True)
    expires = models.DateTimeField(null=True, blank=True)

    def is_expired(self):
        return timezone.now() > self.expires

    def save(self, *args, **kwargs):
        if not self.pk:
            self.expires = timezone.now() + datetime.timedelta(minutes=settings.OTP_EXPIRY)
        super(OTPModel, self).save(*args, **kwargs)

    def __str__(self):
        return f"{self.user.username} | {self.is_expired()}"
