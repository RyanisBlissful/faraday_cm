# authentication/tests.py

from django.urls import reverse
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.core.signing import SignatureExpired, BadSignature

from unittest.mock import patch, MagicMock
from requests import HTTPError

from rest_framework import status
from rest_framework.test import APITestCase


def make_user_data(
    email="newuser@example.com",
    password="StrongPassword123",
    first_name="New",
    last_name="User",
    role="employee",  # must be lowercase per model expectation
):
    return {
        "email": email,
        "password": password,
        "first_name": first_name,
        "last_name": last_name,
        "role": role,
    }


# =========================
# Registration API tests
# =========================
class UserRegistrationTests(APITestCase):
    @patch("authentication.views.send_verification_email")
    def test_user_registration_success(self, send_mock):
        """
        POST /auth/register/ creates an inactive user and attempts to send a verification email.
        Response includes created user data and email_sent=True on success.
        """
        url = reverse("register")
        data = make_user_data()

        resp = self.client.post(url, data, format="json")
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)

        # Response shape
        self.assertIn("user", resp.data)
        self.assertIn("email_sent", resp.data)
        self.assertTrue(resp.data["email_sent"])

        user_payload = resp.data["user"]
        self.assertEqual(user_payload["email"], data["email"])
        self.assertIn("id", user_payload)

        # DB state: user exists and is inactive pending verification
        User = get_user_model()
        user = User.objects.get(email=data["email"])
        self.assertFalse(user.is_active)

        # Email was attempted
        send_mock.assert_called_once()
        # Loosen assertion on args to avoid coupling to subject/template
        called_email = send_mock.call_args.args[0]
        self.assertEqual(called_email, data["email"])

    @patch("authentication.views.send_verification_email")
    def test_token_response_contains_user_info(self, send_mock):
        """
        After registering, once the user is activated (simulating verification),
        the token endpoint returns 200 and includes user info in the response payload.
        """
        # 1) Register (email send mocked)
        registration_url = reverse("register")
        user_data = make_user_data(email="loginok@example.com")
        reg_resp = self.client.post(registration_url, user_data, format="json")
        self.assertEqual(reg_resp.status_code, status.HTTP_201_CREATED)

        # 2) Simulate verification: activate user
        User = get_user_model()
        user = User.objects.get(email=user_data["email"])
        user.is_active = True
        user.save()

        # 3) Obtain token
        token_url = reverse("token_obtain_pair")  # SimpleJWT default name
        token_resp = self.client.post(
            token_url,
            {"email": user_data["email"], "password": user_data["password"]},
            format="json",
        )
        self.assertEqual(token_resp.status_code, status.HTTP_200_OK)

        # 4) Ensure tokens present
        self.assertIn("access", token_resp.data)
        self.assertIn("refresh", token_resp.data)

        # 5) If you have customized the token view to include user info, assert it:
        # (Your earlier tests passed on this, so keep asserting the contract.)
        for key in ("email", "first_name", "last_name", "role"):
            self.assertIn(key, token_resp.data)
        self.assertEqual(token_resp.data["email"], user_data["email"])


    @patch("authentication.views.send_verification_email", side_effect=HTTPError("Graph failure"))
    def test_registration_returns_201_even_if_email_send_fails(self, send_mock):
        """
        If email sending fails, registration should still succeed (201),
        and the response should include email_sent=False.
        """
        url = reverse("register")
        user_data = make_user_data(email="emailfail@example.com")

        resp = self.client.post(url, user_data, format="json")

        # Still a successful registration
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)

        # Response should include email_sent flag
        self.assertIn("email_sent", resp.data)
        self.assertFalse(resp.data["email_sent"])

        # Response should still include created user data
        self.assertIn("user", resp.data)
        self.assertEqual(resp.data["user"]["email"], user_data["email"])

        # Ensure user was created and is inactive pending verification
        User = get_user_model()
        user = User.objects.get(email=user_data["email"])
        self.assertFalse(user.is_active)

        # Verify we attempted to send the email once
        send_mock.assert_called_once()

    @patch("authentication.views.send_verification_email")
    def test_email_verification_flow(self, send_mock):
        """
        Flow:
        - Register user -> inactive and email attempted
        - Attempt login before verification -> 401
        - Mark user active (simulate verification) -> login returns 200
        """
        # Register
        reg_url = reverse("register")
        user_data = make_user_data(email="verifyme@example.com")
        reg_resp = self.client.post(reg_url, user_data, format="json")
        self.assertEqual(reg_resp.status_code, status.HTTP_201_CREATED)

        User = get_user_model()
        user = User.objects.get(email=user_data["email"])
        self.assertFalse(user.is_active)
        send_mock.assert_called_once()

        # Try token before verification (should be 401)
        token_url = reverse("token_obtain_pair")
        token_resp_before = self.client.post(
            token_url,
            {"email": user_data["email"], "password": user_data["password"]},
            format="json",
        )
        self.assertEqual(token_resp_before.status_code, status.HTTP_401_UNAUTHORIZED)

        # Simulate clicking verification link -> activate
        user.is_active = True
        user.save()

        # Try token after verification (should be 200)
        token_resp_after = self.client.post(
            token_url,
            {"email": user_data["email"], "password": user_data["password"]},
            format="json",
        )
        self.assertEqual(token_resp_after.status_code, status.HTTP_200_OK)
        self.assertIn("access", token_resp_after.data)
        self.assertIn("refresh", token_resp_after.data)


# ====================================
# Integration test on email side effect
# ====================================
class RegistrationIntegrationTests(APITestCase):
    @patch("authentication.views.send_verification_email")
    def test_register_returns_201_and_triggers_email(self, send_mock):
        """
        Happy path: registering a user returns 201, creates an inactive user,
        and triggers the email utility once.
        """
        url = reverse("register")
        data = make_user_data(email="integration@example.com")

        resp = self.client.post(url, data, format="json")
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertIn("email_sent", resp.data)
        self.assertTrue(resp.data["email_sent"])

        # User created, inactive
        User = get_user_model()
        user = User.objects.get(email=data["email"])
        self.assertFalse(user.is_active)

        # Email attempted once
        send_mock.assert_called_once()
        called_email = send_mock.call_args.args[0]
        self.assertEqual(called_email, data["email"])


# =========================
# Email utility unit tests
# =========================
class EmailUtilsTests(TestCase):
    @patch("authentication.email_utils.get_access_token", return_value="FAKE_ACCESS_TOKEN")
    @patch("authentication.email_utils.requests.post")
    def test_send_verification_email_posts_graph_payload(self, post_mock, token_mock):
        """
        Ensure our email utility constructs the correct Graph sendMail call:
        - Uses Bearer token from get_access_token()
        - Hits a Graph 'sendMail' endpoint
        - Sends subject, HTML body, and recipient in the expected JSON structure
        """
        from authentication.email_utils import send_verification_email

        # Fake a successful Graph response (202 Accepted)
        post_mock.return_value.status_code = 202
        post_mock.return_value.raise_for_status = MagicMock()

        to_email = "newuser@example.com"
        subject = "Verify your Faraday account"
        html_content = "<p>Please verify</p>"

        # Act
        send_verification_email(to_email, subject, html_content)

        # Assert: requests.post was called
        self.assertTrue(post_mock.called, "requests.post was not called by send_verification_email")

        # Extract call details
        call = post_mock.call_args
        # URL checks: positional arg 0 is URL; if implemented as kwargs, fallback
        url = call.args[0] if call.args else call.kwargs.get("url", "")
        headers = call.kwargs.get("headers", {})
        payload = call.kwargs.get("json", {})

        # URL checks
        self.assertIn("graph.microsoft.com", url)
        self.assertIn("sendMail", url)

        # Header checks
        self.assertEqual(headers.get("Authorization"), "Bearer FAKE_ACCESS_TOKEN")
        self.assertEqual(headers.get("Content-Type"), "application/json")

        # Payload checks (partial but meaningful)
        self.assertEqual(payload["message"]["subject"], subject)
        self.assertEqual(payload["message"]["body"]["contentType"], "HTML")
        self.assertEqual(payload["message"]["body"]["content"], html_content)
        self.assertEqual(
            payload["message"]["toRecipients"][0]["emailAddress"]["address"],
            to_email,
        )

    @patch("authentication.email_utils.get_access_token", return_value="FAKE_ACCESS_TOKEN")
    @patch("authentication.email_utils.requests.post")
    def test_send_verification_email_raises_on_graph_error(self, post_mock, token_mock):
        """
        If Graph returns a non-success status, ensure our utility surfaces the error by
        allowing requests.HTTPError to propagate from raise_for_status().
        """
        from authentication.email_utils import send_verification_email

        # Arrange: fake a 400 response that raises on raise_for_status
        fake_response = MagicMock()
        fake_response.status_code = 400
        http_error = HTTPError("400 Client Error: Bad Request for url", response=fake_response)
        fake_response.raise_for_status.side_effect = http_error
        post_mock.return_value = fake_response

        # Act + Assert
        with self.assertRaises(HTTPError):
            send_verification_email("newuser@example.com", "Subject", "<p>Body</p>")

        # Verify we attempted the POST once
        post_mock.assert_called_once()


class ResendVerificationTests(APITestCase):
    @patch("authentication.views.send_verification_email")
    def test_resend_verification_for_inactive_user_sends_email(self, send_mock):
        """
        If an inactive account exists for the provided email, the endpoint should:
        - return 200
        - include email_sent=True
        - trigger the email utility once
        """
        User = get_user_model()
        user = User.objects.create_user(
            email="inactive@example.com",
            password="StrongPassword123",
            first_name="Ina",
            last_name="Active",
            role="employee",
            is_active=False,  # critical
        )

        url = reverse("resend_verification")
        resp = self.client.post(url, {"email": user.email}, format="json")

        self.assertEqual(resp.status_code, 200)
        self.assertIn("email_sent", resp.data)
        self.assertTrue(resp.data["email_sent"])

        send_mock.assert_called_once()
        called_email = send_mock.call_args.args[0]
        self.assertEqual(called_email, user.email)

    @patch("authentication.views.send_verification_email")
    def test_resend_verification_returns_false_for_active_user(self, send_mock):
        """
        If the user is already active, do not send an email.
        Still return 200 with email_sent=False to avoid account enumeration.
        """
        User = get_user_model()
        user = User.objects.create_user(
            email="active@example.com",
            password="StrongPassword123",
            first_name="Al",
            last_name="Ready",
            role="employee",
            is_active=True,  # already verified
        )

        url = reverse("resend_verification")
        resp = self.client.post(url, {"email": user.email}, format="json")

        self.assertEqual(resp.status_code, 200)
        self.assertIn("email_sent", resp.data)
        self.assertFalse(resp.data["email_sent"])
        send_mock.assert_not_called()



class TokenUtilsTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(
            email="verifytoken@example.com",
            password="StrongPassword123",
            first_name="Veri",
            last_name="Fy",
            role="employee",
            is_active=False,
        )

    def test_generate_and_verify_round_trip(self):
        from authentication.token_utils import (
            generate_email_verification_token,
            verify_email_verification_token,
            get_user_from_verified_payload,
        )

        token = generate_email_verification_token(self.user)
        payload = verify_email_verification_token(token, max_age_hours=48)

        self.assertEqual(payload["email"], self.user.email)
        self.assertEqual(payload["uid"], str(self.user.pk))
        # Ensure we can resolve the user
        resolved = get_user_from_verified_payload(payload)
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved.pk, self.user.pk)

    def test_expired_token_raises(self):
        from authentication.token_utils import (
            generate_email_verification_token,
            verify_email_verification_token,
        )

        token = generate_email_verification_token(self.user)
        # Force immediate expiry by using max_age_hours=0
        with self.assertRaises(SignatureExpired):
            verify_email_verification_token(token, max_age_hours=0)

    def test_bad_token_raises(self):
        from authentication.token_utils import verify_email_verification_token
        with self.assertRaises(BadSignature):
            verify_email_verification_token("this.is.not.a.valid.token")


class VerifyEmailEndpointTests(APITestCase):
    def setUp(self):
        User = get_user_model()
        # Inactive by default per model; activation == verification
        self.user = User.objects.create_user(
            email="verifyendpoint@example.com",
            password="StrongPassword123",
            first_name="Verify",
            last_name="Endpoint",
            role="employee",
            is_active=False,
        )

    def test_verify_email_success(self):
        # Generate a real signed token, then call the endpoint
        from authentication.token_utils import generate_email_verification_token
        token = generate_email_verification_token(self.user)
        url = reverse("verify-email") + f"?token={token}"

        resp = self.client.get(url)

        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertIn("message", resp.data)

        # User should now be active
        User = get_user_model()
        refreshed = User.objects.get(pk=self.user.pk)
        self.assertTrue(refreshed.is_active)

    def test_verify_email_invalid_token(self):
        # Garbage token should be treated as invalid -> 400
        url = reverse("verify-email") + "?token=this.is.not.valid"
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("error", resp.data)
        self.assertEqual(resp.data["error"], "invalid")

    @patch("authentication.views.verify_email_verification_token", side_effect=SignatureExpired("expired"))
    def test_verify_email_expired_token(self, _mock_verify):
        # When verification raises SignatureExpired, view should return 400 "expired"
        url = reverse("verify-email") + "?token=anything"
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("error", resp.data)
        self.assertEqual(resp.data["error"], "expired")

    def test_verify_email_missing_token(self):
        # No token -> 400
        url = reverse("verify-email")
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("error", resp.data)
