import hashlib
import hmac
import os
import secrets
import uuid
from typing import Any, Dict

from app.core.mobile_auth_security import issue_mobile_user_token
from app.core.security import get_jwt_secret_key


ALLOWED_CLIENT_TYPES = {"web", "mobile", "tablet"}


class DeviceAuthSecurityError(Exception):
    pass


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except Exception:
        value = default

    if value < minimum:
        return minimum
    if value > maximum:
        return maximum
    return value


def get_otp_expire_seconds() -> int:
    return _env_int("DEVICE_AUTH_OTP_EXPIRE_SECONDS", 300, 60, 1800)


def get_otp_resend_cooldown_seconds() -> int:
    return _env_int("DEVICE_AUTH_OTP_RESEND_COOLDOWN_SECONDS", 30, 10, 600)


def get_otp_max_attempts() -> int:
    return _env_int("DEVICE_AUTH_OTP_MAX_ATTEMPTS", 5, 1, 20)


def get_otp_max_resends() -> int:
    return _env_int("DEVICE_AUTH_OTP_MAX_RESENDS", 5, 1, 20)


def get_device_trust_days() -> int:
    return _env_int("DEVICE_AUTH_TRUST_DAYS", 90, 1, 365)


def get_refresh_session_days() -> int:
    return _env_int("DEVICE_AUTH_REFRESH_DAYS", 30, 1, 90)


def normalize_client_type(value: Any) -> str:
    client_type = str(value or "mobile").strip().lower()

    if client_type not in ALLOWED_CLIENT_TYPES:
        raise DeviceAuthSecurityError(
            "client_type must be one of: web, mobile, tablet"
        )

    return client_type


def generate_otp() -> str:
    return str(100000 + secrets.randbelow(900000))


def generate_otp_challenge_id() -> str:
    return "LKOTP-" + uuid.uuid4().hex


def generate_login_session_id() -> str:
    return "LKSESS-" + uuid.uuid4().hex + secrets.token_hex(8)


def generate_refresh_token() -> str:
    return secrets.token_urlsafe(64)


def hash_refresh_token(refresh_token: str) -> str:
    return hashlib.sha256(str(refresh_token).encode("utf-8")).hexdigest()


def _get_otp_hash_secret() -> str:
    return (
        str(os.getenv("DEVICE_AUTH_OTP_HASH_SECRET") or "").strip()
        or get_jwt_secret_key()
    )


def hash_otp(
    otp: str,
    challenge_id: str,
    device_id: str,
) -> str:
    message = f"{challenge_id}:{device_id}:{otp}".encode("utf-8")
    return hmac.new(
        _get_otp_hash_secret().encode("utf-8"),
        message,
        hashlib.sha256,
    ).hexdigest()


def verify_otp_hash(
    submitted_otp: str,
    challenge_id: str,
    device_id: str,
    stored_hash: str,
) -> bool:
    expected = hash_otp(
        otp=submitted_otp,
        challenge_id=challenge_id,
        device_id=device_id,
    )

    return hmac.compare_digest(
        expected.lower(),
        str(stored_hash or "").strip().lower(),
    )


def issue_device_access_token(
    user_id: int,
    group_code: str,
    login_point: int,
) -> Dict[str, Any]:
    """
    Keep the existing LogiKlu mobile-user JWT contract for compatibility with
    /auth/web-session. The new /device/* protocol can therefore hand the same
    access token to the existing web-session handoff endpoint without changing
    the old /auth endpoints.
    """
    return issue_mobile_user_token(
        user_id=user_id,
        group_code=group_code,
        login_point=login_point,
    )
