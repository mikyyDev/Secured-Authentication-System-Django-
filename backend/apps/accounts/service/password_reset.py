import hashlib
import secrets
from datetime import timedelta
from urllib.parse import unquote

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db import transaction
from django.utils import timezone

from ..models import PasswordResetToken
from .email_delivery import send_password_reset_email

PASSWORD_RESET_EXPIRATION_MINUTES = 15


def request_password_reset(email):
    """
    Initiate a password reset without revealing whether
    an account exists.
    """
    normalized_email = email.strip().lower()

    # Throttling to prevent email spamming.
    cache_key = f"password-reset-resend:{normalized_email}"
    if not cache.add(cache_key, True, timeout=60):
        return

    User = get_user_model()
    user = User.objects.filter(
        email__iexact=normalized_email,
        is_active=True,
    ).first()

    if user is None:
        return

    with transaction.atomic():
        # Invalidate previous unused reset links for this user.
        PasswordResetToken.objects.filter(
            user=user,
            used_at__isnull=True,
        ).update(used_at=timezone.now())

        raw_token = generate_password_reset_token(user)

        transaction.on_commit(
            lambda: send_password_reset_email(user, raw_token)
        )


def generate_password_reset_token(user):
    """Generate a cryptographically secure token and store only its SHA-256 hash."""
    raw_token = secrets.token_urlsafe(32)

    token_hash = hashlib.sha256(
        raw_token.encode("utf-8")
    ).hexdigest()

    expires_at = timezone.now() + timedelta(
        minutes=PASSWORD_RESET_EXPIRATION_MINUTES
    )

    PasswordResetToken.objects.create(
        user=user,
        token_hash=token_hash,
        expires_at=expires_at,
    )

    return raw_token


def reset_password_with_token(raw_token, new_password):
    """
    Validate the reset token and update the user's password.

    Returns: (user, status_string) where status is 'success', 'expired', or 'invalid'
    """
    if not isinstance(raw_token, str):
        return None, "invalid"

    raw_token = unquote(raw_token).strip()

    if not raw_token or len(raw_token) > 256:
        return None, "invalid"

    token_hash = hashlib.sha256(
        raw_token.encode("utf-8")
    ).hexdigest()

    with transaction.atomic():
        try:
            reset_record = (
                PasswordResetToken.objects
                .select_for_update()
                .select_related("user")
                .get(token_hash=token_hash)
            )
        except PasswordResetToken.DoesNotExist:
            return None, "invalid"

        now = timezone.now()

        if reset_record.used_at is not None:
            return None, "invalid"

        if reset_record.expires_at <= now:
            return None, "expired"

        user = reset_record.user

        user.set_password(new_password)
        user.save(update_fields=["password"])

        reset_record.used_at = now
        reset_record.save(update_fields=["used_at"])

    return user, "success"

