from rest_framework import permissions


class ReviewCommentPermission(permissions.BasePermission):

    def __init__(self, request, view, obj):
        self.request = request
        self.view = view
        self.obj = obj

    def has_permission(self):

        return(
            self.request.method in permissions.SAFE_METHODS
            or self.request.user.is_authenticated
        )

    def has_object_permission(self):

        if (
            self.request.method in permissions.SAFE_METHODS
            or self.obj.author == self.request.user
        ):
            return True

        return (
            self.request.method in permissions.SAFE_METHODS
            or self.obj.author == self.request.user
            or self.request.user.role == self.request.user.Role.MODERATOR
            or self.request.user.role == self.request.user.Role.ADMIN
        )


class IsSuperUserOrReadOnly(permissions.BasePermission):

    def __init__(self, request, view):
        self.request = request
        self.view = view

    def has_permission(self):

        return (
            self.request.method in permissions.SAFE_METHODS
            or self.request.user.is_superuser
        )
