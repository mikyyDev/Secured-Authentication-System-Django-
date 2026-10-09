
import hashlib
import secrets
from datetime import timedelta
from urllib.parse import unquote

from django.core.cache import cache
from django.db import transaction
from django.utils import timezone

from ..models import EmailVerificationToken
from .email_delivery import send_verification_email

TOKEN_EXPIRATION_MINUTES = 30


def request_email_verification(email):
    """
    Request a verification email without revealing whether
    an account exists.
    """

    normalized_email = email.strip().lower()

    # Basic resend throttling for this email address.
    cache_key = (
        f"email-verification-resend:{normalized_email}"
    )

    if not cache.add(cache_key, True, timeout=60):
        return

    from django.contrib.auth import get_user_model

    User = get_user_model()

    user = User.objects.filter(
        email__iexact=normalized_email,
        is_active=True,
    ).first()

    if user is None or user.email_verified:
        return

    with transaction.atomic():
        # Invalidate previous unused verification links.
        EmailVerificationToken.objects.filter(
            user=user,
            used_at__isnull=True,
        ).update(used_at=timezone.now())

        raw_token = generate_email_verification_token(user)

        transaction.on_commit(
            lambda: send_verification_email(user, raw_token)
        )


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

    if not isinstance(raw_token, str):
        return "invalid"

    raw_token = unquote(raw_token).strip()

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