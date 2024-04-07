from django.db import models
from django.contrib.auth.models import AbstractUser


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

