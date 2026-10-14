from django.contrib.auth import login, logout
from django.http import JsonResponse
from django.middleware.csrf import get_token
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie
from django.views.decorators.http import require_GET
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .serializers import (
    LoginSerializer,
    RegisterSerializer,
    ResendVerificationSerializer,
    UserSerializer,
)
from .service.authentication import authenticate_user
from .service.email_verification import (
    request_email_verification,
    verify_email_token,
)
from .service.registration import register_user


@require_GET
@ensure_csrf_cookie
def csrf_cookie_view(request):
    return JsonResponse({
        "csrfToken": get_token(request)
    })


@method_decorator(csrf_protect, name="dispatch")
class CsrfProtectedAPIView(APIView):
    pass


class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        logout(request)

        return Response(
            {"detail": "Logout successful."},
            status=status.HTTP_200_OK,
        )

class MeView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        serializer = UserSerializer(request.user)

        return Response(
            serializer.data,
            status=status.HTTP_200_OK,
        )



class LoginView(CsrfProtectedAPIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = authenticate_user(
            request,
            identifier=serializer.validated_data["identifier"],
            password=serializer.validated_data["password"],
        )

        if user is None:
            return Response(
                {
                    "detail": (
                        "Invalid credentials or account not verified."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        login(request, user)

        return Response(
            {
                "user": UserSerializer(user).data,
                "detail": "Login successful.",
            },
            status=status.HTTP_200_OK,
        )

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