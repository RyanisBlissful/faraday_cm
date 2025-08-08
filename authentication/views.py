from django.shortcuts import render

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework  import status
from rest_framework.permissions import IsAuthenticated

from .permissions import IsAdmin, IsManage
from .serializers import RegisterUserSerializer


# Create your views here.

class RegisterUserView(APIView):
    def post(self, request):
        serializer = RegisterUserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response(RegisterUserSerializer(user).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class MeView(APIView):
    """
    Simple authenticated endpoint that returns the current user's basic info.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        data = {
            "id": user.id,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "role": getattr(user, "role", None),
        }
        return Response(data, status=status.HTTP_200_OK)