from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from .serializers import (
    RegisterSerializer,
    ResendVerificationSerializer,
    UserSerializer,
)
from .service.email_verification import (
    request_email_verification,
    verify_email_token,
)
from .service.registration import register_user


class RegisterView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = register_user(serializer=serializer)

        return Response(
            {
                "user": UserSerializer(user).data,
                "detail": (
                    "Account created. Please check your email "
                    "to verify your address."
                ),
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
    
class ResendVerificationView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = ResendVerificationSerializer(
            data=request.data
        )
        serializer.is_valid(raise_exception=True)

        request_email_verification(
            serializer.validated_data["email"]
        )

        return Response(
            {
                "detail": (
                    "If an account requires verification, "
                    "instructions will be sent shortly."
                )
            },
            status=status.HTTP_200_OK,
        )