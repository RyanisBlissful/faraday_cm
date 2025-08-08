from rest_framework.test import APITestCase
from rest_framework import status
from django.urls import reverse

class UserRegistrationTests(APITestCase):
    def test_user_registration_success(self):
        url = reverse('register-new-user')
        data = {
            "email": "testuser@example.com",
            "password": "StrongPassword123!",
            "first_name": "Test",
            "last_name": "User",
            "role": "employee",

        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn("id", response.data)  # Adjust if your response uses a different key
