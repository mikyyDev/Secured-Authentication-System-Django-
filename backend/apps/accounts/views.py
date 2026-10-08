from django.db import transaction
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from .serializers import RegisterSerializer, UserSerializer
from .service.email_verification import (
    generate_email_verification_token,
    verify_email_token,
)


class RegisterView(APIView):

    @transaction.atomic
    def post(self, request):
        serializer = RegisterSerializer(
            data=request.data
        )

        serializer.is_valid(raise_exception=True)

        user = serializer.save()

        verification_token = generate_email_verification_token(
            user
        )

        return Response(
            {
                "user": UserSerializer(user).data,
                "verification_token": verification_token,
            },
            status=status.HTTP_201_CREATED,
        )
    
class VerifyEmailView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        token = request.data.get("token")

        if not isinstance(token, str):
            return Response(
                {"detail": "A valid verification token is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        result = verify_email_token(token)

        if result == "success":
            return Response(
                {"detail": "Email verified successfully."},
                status=status.HTTP_200_OK,
            )

        if result == "already_verified":
            return Response(
                {"detail": "This email has already been verified."},
                status=status.HTTP_200_OK,
            )

        if result == "expired":
            return Response(
                {
                    "detail": (
                        "This verification link has expired. "
                        "Request a new verification email."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response(
            {"detail": "Invalid verification token."},
            status=status.HTTP_400_BAD_REQUEST,
        )