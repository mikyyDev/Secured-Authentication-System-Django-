
from django.contrib.auth import authenticate, get_user_model

User = get_user_model()


def authenticate_user(request, *, identifier, password):
    """
    Authenticate using username or email.

    Returns a user if credentials are valid; otherwise None.
    """

    identifier = identifier.strip()

    # Find the account using either username or email.
    user = User.objects.filter(
        email__iexact=identifier
    ).first()

    if user is None:
        user = User.objects.filter(
            username__iexact=identifier
        ).first()

    if user is None:
        # Run Django's password hashing check against a dummy
        # hash to reduce timing differences for unknown users.
        User().set_password(password)
        return None

    if not user.is_active:
        return None

    authenticated_user = authenticate(
        request=request,
        username=user.username,
        password=password,
    )

    if authenticated_user is None:
        return None

    if not authenticated_user.email_verified:
        return None

    return authenticated_user