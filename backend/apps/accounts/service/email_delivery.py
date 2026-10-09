
from urllib.parse import quote

from django.conf import settings
from django.core.mail import send_mail


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

    return send_mail(
        subject=subject,
        message=message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False,
    )