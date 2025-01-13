from django.contrib.auth.hashers import make_password, check_password, get_hasher
from django.test import TestCase


class PasswordHasherTest(TestCase):
    def test_active_hasher(self):
        # Get the currently active hasher
        hasher = get_hasher()

        # Check that the hasher is the one configured (e.g., Argon2)
        self.assertEqual(hasher.algorithm, 'argon2')

    def test_password_hashing_and_verification(self):
        # Password to test
        plain_password = 'securepassword123'

        # Hash the password
        hashed_password = make_password(plain_password)

        # Verify the hashed password format
        self.assertTrue(hashed_password.startswith('argon2$argon2'))

        # Check that the password matches the hash
        self.assertTrue(check_password(plain_password, hashed_password))

    def test_invalid_password(self):
        # Password to test
        plain_password = 'securepassword123'
        wrong_password = 'wrongpassword'

        # Hash the correct password
        hashed_password = make_password(plain_password)

        # Check that an incorrect password does not match the hash
        self.assertFalse(check_password(wrong_password, hashed_password))
