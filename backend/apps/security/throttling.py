from rest_framework.throttling import SimpleRateThrottle

from .utils import get_client_ip


class LoginRateThrottle(SimpleRateThrottle):
    """Throttle login attempts by IP and identifier to prevent brute force attacks."""
    scope = "login"

    def get_cache_key(self, request, view):
        ip = get_client_ip(request)
        identifier = ""
        if hasattr(request, "data") and isinstance(request.data, dict):
            identifier = str(request.data.get("identifier", "")).strip().lower()

        if identifier:
            ident = f"{ip}:{identifier}"
        else:
            ident = ip

        return self.cache_format % {
            "scope": self.scope,
            "ident": ident,
        }


class ForgotPasswordRateThrottle(SimpleRateThrottle):
    """Throttle password reset requests to prevent email bombing."""
    scope = "forgot_password"

    def get_cache_key(self, request, view):
        ip = get_client_ip(request)
        email = ""
        if hasattr(request, "data") and isinstance(request.data, dict):
            email = str(request.data.get("email", "")).strip().lower()

        if email:
            ident = f"{ip}:{email}"
        else:
            ident = ip

        return self.cache_format % {
            "scope": self.scope,
            "ident": ident,
        }


class ResetPasswordSubmitRateThrottle(SimpleRateThrottle):
    """Throttle reset confirmation attempts to protect against token brute forcing."""
    scope = "reset_password"

    def get_cache_key(self, request, view):
        ip = get_client_ip(request)
        return self.cache_format % {
            "scope": self.scope,
            "ident": ip,
        }
