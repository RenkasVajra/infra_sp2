from rest_framework import permissions

from .models import User


class IsAdmin(permissions.BasePermission):
    def __init__(self, request, view, obj):
        self.request = request
        self.view = view
        self.obj = obj

    def has_permission(self):
        return (
            hasattr(self.request.user, 'role')
            and self.request.user.role == User.Role.ADMIN
            or self.request.user.is_superuser
        )


class IsModerator(permissions.BasePermission):

    def has_permission(self):
        return (
            hasattr(self.request.user, 'role')
            and self.request.user.role == User.Role.MODERATOR
        )


class IsUser(permissions.BasePermission):

    def has_permission(self):
        return (
            hasattr(self.request.user, 'role')
            and self.request.user.role == User.Role.USER
        )


class IsOwner(permissions.BasePermission):

    def has_object_permission(self):
        return (
            self.obj.email == self.request.user
            or self.request.method in permissions.SAFE_METHODS
        )
