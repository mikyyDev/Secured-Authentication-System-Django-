
from django.urls import path

from .views import (
    LoginView,
    LogoutView,
    MeView,
    RegisterView,
    ResendVerificationView,
    VerifyEmailView,
    csrf_cookie_view,
)

urlpatterns = [
    path("csrf/", csrf_cookie_view, name="csrf-cookie"),
    path("register/", RegisterView.as_view(), name="register"),
    path("verify-email/", VerifyEmailView.as_view(), name="verify-email"),
    path(
        "resend-verification/",
        ResendVerificationView.as_view(),
        name="resend-verification",
    ),
    path("login/", LoginView.as_view(), name="login"),
    path("me/", MeView.as_view(), name="me"),
    path("logout/", LogoutView.as_view(), name="logout"),
]