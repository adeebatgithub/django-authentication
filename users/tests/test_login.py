from django.conf import settings
from django.contrib import auth
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

User = get_user_model()


class TestLogin(TestCase):
    url = reverse("users:login")

    def setUp(self):
        # Create test user
        self.test_user_username = "test_user"
        self.test_user_password = "qwerty@123"
        self.test_user_email = "testuser@test.com"
        self.test_user = User.objects.create_user(
            username=self.test_user_username,
            email=self.test_user_email,
            password=self.test_user_password
        )

        # Create admin user
        self.admin_username = "root"
        self.admin_password = "root"
        self.admin_user = User.objects.create_superuser(
            username=self.admin_username,
            email="admin@example.com",
            password=self.admin_password
        )

        # Set second factor verification status if applicable
        self.test_user.second_factor_verified = False
        self.test_user.save()

    def test_login_required(self):
        profile_url = reverse("users:redirect-user")
        response = self.client.get(profile_url)
        self.assertEqual(response.status_code, 302)
        # Ensure the user is redirected to login page with 'next' parameter
        expected_url = settings.LOGIN_REDIRECT_URL
        self.assertRedirects(response, expected_url)

    def test_template(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "users/general/login.html")

    def test_wrong_credentials(self):
        response = self.client.post(self.url, {
            "username": self.test_user_username,
            "password": "wrongpassword"
        })
        user = auth.get_user(self.client)
        self.assertFalse(user.is_authenticated)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Invalid username or password.")

    def test_username_login(self):
        response = self.client.post(self.url, {
            "username": self.test_user_username,
            "password": self.test_user_password
        })
        user = auth.get_user(self.client)
        self.assertTrue(user.is_authenticated)
        self.assertEqual(response.status_code, 302)
        # Optionally, check the redirect target
        # self.assertRedirects(response, reverse(settings.SECOND_FACTOR_VERIFICATION_URL))

    def test_email_login(self):
        response = self.client.post(self.url, {
            "username": self.test_user_email,
            "password": self.test_user_password
        })
        user = auth.get_user(self.client)
        self.assertTrue(user.is_authenticated)
        self.assertEqual(response.status_code, 302)
        # Optionally, check the redirect target
        # self.assertRedirects(response, reverse(settings.SECOND_FACTOR_VERIFICATION_URL))

    def test_admin_redirection(self):
        response = self.client.post(self.url, {
            "username": self.admin_username,
            "password": self.admin_password
        }, follow=True)

        user = auth.get_user(self.client)
        self.assertTrue(user.is_authenticated)
        self.assertTrue(user.is_superuser)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.request['PATH_INFO'], reverse("admin:index"))

    def test_user_redirection(self):
        response = self.client.post(self.url, {
            "username": self.test_user_username,
            "password": self.test_user_password
        }, follow=True)
        print(response.redirect_chain)
        user = auth.get_user(self.client)
        self.assertTrue(user.is_authenticated)
        self.assertEqual(response.status_code, 200)
        self.assertIn("/2FA/email/verify/", response.request["PATH_INFO"])
