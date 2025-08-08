# authentication/permissions.py
from rest_framework.permissions import BasePermission

class IsAdmin(BasePermission):
    """
    Allows access only to authenticated users with role == 'admin'.
    """
    def has_permission(self, request, view):
        user = request.user
        return bool(user and user.is_authenticated and getattr(user, "role", None) == "admin")


class IsManage(BasePermission):
    """
    Allows access to authenticated users with role in {'admin', 'manager'}.
    """
    def has_permission(self, request, view):
        user = request.user
        return bool(user and user.is_authenticated and getattr(user, "role", None) in {"admin", "manager"})
