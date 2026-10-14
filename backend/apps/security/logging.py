import logging

from .utils import get_client_ip, mask_email

logger = logging.getLogger("security")


def log_login_success(request, user):
    ip = get_client_ip(request)
    logger.info(
        f"[LOGIN_SUCCESS] user_id={user.pk} username={user.username} ip={ip}"
    )


def log_login_failure(request, identifier, reason="invalid_credentials"):
    ip = get_client_ip(request)
    masked_identifier = mask_email(identifier) if "@" in identifier else identifier
    logger.warning(
        f"[LOGIN_FAILED] identifier={masked_identifier} reason={reason} ip={ip}"
    )


def log_logout(request, user):
    ip = get_client_ip(request)
    user_id = getattr(user, "pk", "anonymous")
    logger.info(f"[LOGOUT] user_id={user_id} ip={ip}")


def log_password_reset_request(request, email):
    ip = get_client_ip(request)
    masked = mask_email(email)
    logger.info(f"[PASSWORD_RESET_REQUESTED] email={masked} ip={ip}")


def log_password_reset_success(request, user):
    ip = get_client_ip(request)
    logger.info(f"[PASSWORD_RESET_SUCCESS] user_id={user.pk} ip={ip}")


def log_password_reset_failure(request, reason):
    ip = get_client_ip(request)
    logger.warning(f"[PASSWORD_RESET_FAILED] reason={reason} ip={ip}")


def log_email_delivery_failure(email, reason):
    masked = mask_email(email)
    logger.error(f"[EMAIL_DELIVERY_FAILED] email={masked} error={reason}")
