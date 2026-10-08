
import hashlib
import secrets
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from ..models import EmailVerificationToken

TOKEN_EXPIRATION_MINUTES = 30


def generate_email_verification_token(user):
    """Generate a secure token and store only its SHA-256 hash."""

    raw_token = secrets.token_urlsafe(32)

    token_hash = hashlib.sha256(
        raw_token.encode("utf-8")
    ).hexdigest()

    expires_at = timezone.now() + timedelta(
        minutes=TOKEN_EXPIRATION_MINUTES
    )

    EmailVerificationToken.objects.create(
        user=user,
        token_hash=token_hash,
        expires_at=expires_at,
    )

    return raw_token


def verify_email_token(raw_token):
    """
    Validate a verification token and verify the user's email.

    Returns a status string describing the outcome.
    """

    if not raw_token or len(raw_token) > 256:
        return "invalid"

    token_hash = hashlib.sha256(
        raw_token.encode("utf-8")
    ).hexdigest()

    with transaction.atomic():
        try:
            verification = (
                EmailVerificationToken.objects
                .select_for_update()
                .select_related("user")
                .get(token_hash=token_hash)
            )
        except EmailVerificationToken.DoesNotExist:
            return "invalid"

        now = timezone.now()

        if verification.used_at is not None:
            return "invalid"

        if verification.expires_at <= now:
            return "expired"

        user = verification.user

        if user.email_verified:
            verification.used_at = now
            verification.save(update_fields=["used_at"])
            return "already_verified"

        user.email_verified = True
        user.save(update_fields=["email_verified"])

        verification.used_at = now
        verification.save(update_fields=["used_at"])

    return "success"