from django.contrib.auth.hashers import Argon2PasswordHasher


class Hasher(Argon2PasswordHasher):
    time_cost = 4  # Default: 2, increase to slow down brute-force
    memory_cost = 512 * 1024  # Default: 102400 KiB, increase for more memory hardness
    parallelism = 4  # Default: 8, adjust based on your server capabilities
