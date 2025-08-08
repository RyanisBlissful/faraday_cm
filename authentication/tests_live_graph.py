# authentication/tests_live_graph.py
import os
from unittest import skipUnless

from django.test import SimpleTestCase, override_settings

from authentication.email_utils import get_access_token, send_verification_email

RUN_LIVE = os.getenv("RUN_GRAPH_LIVE_TESTS") == "1"


@skipUnless(RUN_LIVE, "Set RUN_GRAPH_LIVE_TESTS=1 to run live Microsoft Graph tests")
class GraphLiveEmailTests(SimpleTestCase):
    """
    LIVE integration tests for Microsoft Graph (opt-in).
    These tests make real network calls and will attempt to send an email.
    """

    def test_can_get_access_token_live(self):
        """
        Verifies we can acquire a real Graph access token using client credentials.
        """
        token = get_access_token()  # raises on HTTP error
        self.assertIsInstance(token, str)
        self.assertGreater(len(token), 100)  # sanity check on token length

    def test_can_send_verification_email_live(self):
        """
        Verifies we can send a real email via Graph 'sendMail' (returns 202 on success).
        """
        recipient = os.getenv("LIVE_GRAPH_RECIPIENT")
        self.assertTrue(
            recipient,
            "Set LIVE_GRAPH_RECIPIENT in the environment to run this test.",
        )

        subject = "Faraday_CM Live Test — OK to ignore"
        html = "<p>This is a live test from Faraday_CM.</p>"

        # Optionally override the sender for this test (defaults to settings.EMAIL_ADDRESS or EMAIL_HOST_USER).
        sender = os.getenv("LIVE_GRAPH_SENDER")
        if sender:
            with override_settings(EMAIL_ADDRESS=sender):
                send_verification_email(recipient, subject, html)  # raises on error
        else:
            send_verification_email(recipient, subject, html)  # raises on error

        # If no exception was raised, Graph accepted the request (202).
        # Our email_utils raises on non-success, so reaching here means success.
