from django.contrib.auth.hashers import Argon2PasswordHasher


class Hasher(Argon2PasswordHasher):
    time_cost = 4
    memory_cost = 512 * 1024
    parallelism = 4
