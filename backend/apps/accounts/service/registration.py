
from django.db import transaction

from .email_delivery import send_verification_email
from .email_verification import generate_email_verification_token


@transaction.atomic
def register_user(*, serializer):
    user = serializer.save()

    raw_token = generate_email_verification_token(user)

    # Run after the database transaction commits.
    transaction.on_commit(
        lambda: send_verification_email(user, raw_token)
    )

    return user