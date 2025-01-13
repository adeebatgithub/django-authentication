from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse


class TestRegister(TestCase):
    url = reverse("users:register")
    UserModel = get_user_model()

    def setUp(self):
        # Create an existing user for uniqueness tests
        self.existing_username = "existing_user"
        self.existing_email = "existing@example.com"
        self.existing_password = "ExistingPass123"
        self.existing_user = self.UserModel.objects.create_user(
            username=self.existing_username,
            email=self.existing_email,
            password=self.existing_password
        )

    def test_template_used(self):
        """
        Test that the registration page uses the correct template.
        """
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "users/general/register.html")

    def test_successful_registration(self):
        """
        Test that a user can register with valid data.
        """
        response = self.client.post(self.url, {
            "username": "new_user",
            "email": "newuser@example.com",
            "password1": "StrongPass123!",
            "password2": "StrongPass123!",
        })
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse("users:add-example-role"))
        user_exists = self.UserModel.objects.filter(username="new_user").exists()
        self.assertTrue(user_exists)
        user = self.UserModel.objects.get(username="new_user")
        self.assertTrue(user.is_active)
        # If your app sends a confirmation email
        # self.assertEqual(len(mail.outbox), 1)
        # email = mail.outbox[0]
        # self.assertIn("Please confirm your email", email.subject)

    def test_username_already_exists(self):
        """
        Test that registering with an existing username raises an error.
        """
        response = self.client.post(self.url, {
            "username": self.existing_username,
            "email": "unique_email@example.com",
            "password1": "StrongPass123!",
            "password2": "StrongPass123!",
        })
        self.assertEqual(response.status_code, 200)
        form = response.context['form']
        self.assertTrue(form.errors)
        self.assertIn('username', form.errors)
        self.assertFormError(response, 'form', 'username', 'A user with that username already exists.')

    def test_email_already_exists(self):
        """
        Test that registering with an existing email raises an error.
        """
        response = self.client.post(self.url, {
            "username": "unique_username",
            "email": self.existing_email,
            "password1": "StrongPass123!",
            "password2": "StrongPass123!",
        })
        self.assertEqual(response.status_code, 200)
        form = response.context['form']
        self.assertTrue(form.errors)
        self.assertIn('email', form.errors)
        self.assertFormError(response, 'form', 'email', 'Email already exists')

    def test_password_mismatch(self):
        """
        Test that the form errors when passwords do not match.
        """
        response = self.client.post(self.url, {
            "username": "test_user",
            "email": "user@example.com",
            "password1": "StrongPass123!",
            "password2": "DifferentPass123!",
        })
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, 'form', 'password2', "The two password fields didn't match.")

    def test_invalid_email_format(self):
        """
        Test that the form errors when an invalid email is provided.
        """
        response = self.client.post(self.url, {
            "username": "test_user",
            "email": "invalid-email",
            "password1": "StrongPass123!",
            "password2": "StrongPass123!",
        })
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, 'form', 'email', 'Enter a valid email address.')

    def test_missing_required_fields(self):
        """
        Test that the form errors when required fields are missing.
        """
        response = self.client.post(self.url, {})
        self.assertEqual(response.status_code, 200)
        required_fields = ['username', 'email', 'password1', 'password2']
        for field in required_fields:
            self.assertFormError(response, 'form', field, 'This field is required.')

    def test_weak_password(self):
        """
        Test that the form errors when a weak password is provided.
        """
        response = self.client.post(self.url, {
            "username": "test_user",
            "email": "user@example.com",
            "password1": "password",
            "password2": "password",
        })
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, 'form', 'password2', 'This password is too common.')

    def test_short_password(self):
        """
        Test that the form errors when the password is too short.
        """
        response = self.client.post(self.url, {
            "username": "test_user",
            "email": "user@example.com",
            "password1": "short",
            "password2": "short",
        })
        self.assertEqual(response.status_code, 200)
        self.assertFormError(
            response, 'form', 'password2',
            'This password is too short. It must contain at least 8 characters.'
        )

    def test_numeric_password(self):
        """
        Test that the form errors when the password is entirely numeric.
        """
        response = self.client.post(self.url, {
            "username": "test_user",
            "email": "user@example.com",
            "password1": "12345678",
            "password2": "12345678",
        })
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, 'form', 'password2', 'This password is entirely numeric.')

    def test_max_length_username(self):
        """
        Test that the form errors when the username exceeds max length.
        """
        long_username = 'u' * 151  # Assuming max_length is 150
        response = self.client.post(self.url, {
            "username": long_username,
            "email": "user@example.com",
            "password1": "StrongPass123!",
            "password2": "StrongPass123!",
        })
        self.assertEqual(response.status_code, 200)
        form = response.context['form']
        self.assertFormError(
            response, 'form', 'username',
            'Ensure this value has at most 150 characters (it has 151).'
        )

    def test_unicode_username(self):
        """
        Test that a user can register with a username containing Unicode characters.
        """
        unicode_username = '测试用户'
        response = self.client.post(self.url, {
            "username": unicode_username,
            "email": "unicode@example.com",
            "password1": "StrongPass123!",
            "password2": "StrongPass123!",
        })
        self.assertEqual(response.status_code, 302)
        user_exists = self.UserModel.objects.filter(username=unicode_username).exists()
        self.assertTrue(user_exists)

    def test_csrf_protection(self):
        """
        Test that the form rejects submissions without a CSRF token.
        """
        # Remove CSRF middleware to simulate missing CSRF token
        middleware = 'django.middleware.csrf.CsrfViewMiddleware'
        settings.MIDDLEWARE.remove(middleware)
        response = self.client.post(self.url, {
            "username": "testuser",
            "email": "user@example.com",
            "password1": "StrongPass123!",
            "password2": "StrongPass123!",
        })
        # CSRF protection should prevent form submission
        self.assertEqual(response.status_code, 403)
        # Re-add middleware for other tests
        settings.MIDDLEWARE.insert(0, middleware)

    def test_terms_and_conditions_unchecked(self):
        """
        Test that the form errors when terms and conditions are not accepted.
        """
        # Assuming your form has a 'terms' BooleanField
        response = self.client.post(self.url, {
            "username": "test_user",
            "email": "user@example.com",
            "password1": "StrongPass123!",
            "password2": "StrongPass123!",
            # "terms": "on",  # Not included to simulate unchecked
        })
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, 'form', 'terms', 'You must accept the terms and conditions.')

    def test_sql_injection_attempt(self):
        """
        Test that the form is safe from SQL injection attempts.
        """
        malicious_username = "'; DROP TABLE users; --"
        response = self.client.post(self.url, {
            "username": malicious_username,
            "email": "user@example.com",
            "password1": "StrongPass123!",
            "password2": "StrongPass123!",
        })
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, 'form', 'username', 'Enter a valid username.')

    def test_html_injection_attempt(self):
        """
        Test that the form sanitizes input to prevent XSS attacks.
        """
        malicious_username = "<script>alert('XSS');</script>"
        response = self.client.post(self.url, {
            "username": malicious_username,
            "email": "user@example.com",
            "password1": "StrongPass123!",
            "password2": "StrongPass123!",
        })
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, 'form', 'username', 'Enter a valid username.')

    def test_invalid_password_complexity(self):
        """
        Test that the form errors when the password doesn't meet complexity requirements.
        """
        # Assuming you have custom validators for password complexity
        response = self.client.post(self.url, {
            "username": "test_user",
            "email": "user@example.com",
            "password1": "NoNumbers!",
            "password2": "NoNumbers!",
        })
        self.assertEqual(response.status_code, 200)
        self.assertFormError(
            response, 'form', 'password2',
            'Password must contain at least one numeral.'
        )

    def test_email_field_max_length(self):
        """
        Test that the form errors when the email exceeds max length.
        """
        long_email = 'a' * 245 + '@example.com'  # Assuming max_length is 254
        response = self.client.post(self.url, {
            "username": "test_user",
            "email": long_email,
            "password1": "StrongPass123!",
            "password2": "StrongPass123!",
        })
        self.assertEqual(response.status_code, 200)
        self.assertFormError(
            response, 'form', 'email',
            'Enter a valid email address.'
        )

    def test_duplicate_registration_attempt(self):
        """
        Test that the same user cannot register twice.
        """
        # First registration attempt
        self.client.post(self.url, {
            "username": "unique_user",
            "email": "unique@example.com",
            "password1": "StrongPass123!",
            "password2": "StrongPass123!",
        })
        # Second registration attempt with the same credentials
        response = self.client.post(self.url, {
            "username": "unique_user",
            "email": "unique@example.com",
            "password1": "StrongPass123!",
            "password2": "StrongPass123!",
        })
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, 'form', 'username', 'A user with that username already exists.')
        self.assertFormError(response, 'form', 'email', 'Email already exists')
