
from urllib.parse import quote

from django.conf import settings
from django.core.mail import send_mail

from apps.security.logging import log_email_delivery_failure


def send_verification_email(user, raw_token):
    encoded_token = quote(raw_token, safe="")
    verification_url = (
        f"{settings.FRONTEND_URL}/verify-email"
        f"?token={encoded_token}"
    )

    subject = "Verify your AuthForge email address"

    message = (
        f"Hello {user.username},\n\n"
        "Thank you for registering with AuthForge.\n\n"
        "Please open the following link to verify your email:\n\n"
        f"{verification_url}\n\n"
        "This link expires in 30 minutes.\n\n"
        "If you did not create this account, you can ignore "
        "this email."
    )

    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )
        return True
    except Exception as exc:
        log_email_delivery_failure(user.email, str(exc))
        return False


def send_password_reset_email(user, raw_token):
    encoded_token = quote(raw_token, safe="")
    reset_url = (
        f"{settings.FRONTEND_URL}/reset-password"
        f"?token={encoded_token}"
    )

    subject = "Reset your AuthForge password"

    message = (
        f"Hello {user.username},\n\n"
        "We received a request to reset your AuthForge password.\n\n"
        "Please open the following link to choose a new password:\n\n"
        f"{reset_url}\n\n"
        "This link expires in 15 minutes.\n\n"
        "If you did not request a password reset, you can safely "
        "ignore this email. Your password will remain unchanged."
    )

    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )
        return True
    except Exception as exc:
        log_email_delivery_failure(user.email, str(exc))
        return False
