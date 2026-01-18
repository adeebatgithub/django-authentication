from django.contrib import admin

from users.models import *


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'email_verified', 'lock_status', 'second_factor_verified')


@admin.register(OTPModel)
class OTPModelAdmin(admin.ModelAdmin):
    list_display = ('user', 'otp')

@admin.register(TokenModel)
class TokenModelAdmin(admin.ModelAdmin):
    list_display = ('user', 'token')
