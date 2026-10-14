def get_client_ip(request):
    """Safely extract client IP from request, handling proxy headers."""
    if not request:
        return "unknown"

    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0].strip()
    else:
        ip = request.META.get("REMOTE_ADDR", "unknown")
    return ip


def mask_email(email):
    """
    Mask email address for safe logging.
    Example: 'michael@example.com' -> 'm***l@example.com'
    """
    if not email or "@" not in email:
        return "invalid-email"

    name, domain = email.split("@", 1)
    if len(name) <= 2:
        masked_name = name[0] + "*"
    else:
        masked_name = name[0] + "*" * (len(name) - 2) + name[-1]

    return f"{masked_name}@{domain}"
