import datetime

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone

app_name = 'users'


class User(AbstractUser):
    LOCK_NONE = 0
    LOCK_TEMPORARY = 1
    LOCK_PERMANENT = 2
    LOCK_PENDING = 3
    LOCK_STATUS = (
        (LOCK_NONE, "not locked"),
        (LOCK_TEMPORARY, "temporarily"),
        (LOCK_PERMANENT, "permanently"),
        (LOCK_PENDING, "pending lock verification"),
    )

    email_verified = models.BooleanField(default=False)

    login_attempts = models.PositiveSmallIntegerField(default=0)
    lock_status = models.PositiveSmallIntegerField(default=0, choices=LOCK_STATUS)

    second_factor_verified = models.BooleanField(default=False)

    def __str__(self):
        return self.username

    def is_member(self, group):
        return self.groups.filter(name=group).exists()

    def is_locked(self):
        return self.lock_status != self.LOCK_NONE

    def is_email_verified(self):
        return self.email_verified

    def verify_second_factor(self):
        if not self.second_factor_verified:
            self.second_factor_verified = True
            self.save()

    def un_verify_second_factor(self):
        if self.second_factor_verified:
            self.second_factor_verified = False
            self.save()

    def temporarily_lock_user(self):
        self.is_locked = True
        self.lock_status = self.LOCK_TEMPORARY
        self.save()

    def un_lock_user(self):
        self.lock_status = self.LOCK_NONE
        self.save()

    def permanently_lock_user(self):
        self.is_locked = True
        self.lock_status = self.LOCK_PERMANENT
        self.save()

    def increment_login_attempts(self):
        self.login_attempts += 1
        if self.login_attempts == settings.MIN_LOGIN_ATTEMPT_LIMIT - 1:
            return self.temporarily_lock_user()
        if self.login_attempts == settings.MAX_LOGIN_ATTEMPT_LIMIT - 1:
            return self.permanently_lock_user()
        self.save()

    def reset_login_attempts(self):
        if self.login_attempts > 0:
            self.login_attempts = 0
            self.save()


class OTPModel(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=settings.OTP_LENGTH, null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True)
    expires = models.DateTimeField(null=True, blank=True)

    def is_expired(self):
        return timezone.localtime() > self.expires

    @staticmethod
    def get_otp_expiry():
        if hasattr(settings, 'OTP_EXPIRY'):
            return settings.OTP_EXPIRY
        return {"minutes": 30}

    def save(self, *args, **kwargs):
        if not self.pk:
            self.expires = timezone.localtime() + datetime.timedelta(**self.get_otp_expiry())
        super().save(*args, **kwargs)


class TokenModel(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=255)
    created = models.DateTimeField(auto_now_add=True)
    expires = models.DateTimeField(null=True, blank=True)

    def is_expired(self):
        return timezone.now() > self.expires

    @staticmethod
    def get_token_expiry():
        if hasattr(settings, 'TOKEN_EXPIRY'):
            return settings.TOKEN_EXPIRY
        return {"minutes": 10}

    def save(self, *args, **kwargs):
        if not self.pk:
            self.expires = timezone.localtime() + datetime.timedelta(**self.get_token_expiry())
        super(TokenModel, self).save(*args, **kwargs)
