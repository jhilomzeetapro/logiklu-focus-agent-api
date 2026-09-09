import hashlib
import hmac
import os
import secrets
from datetime import date, datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

from app.common.mail_helper import (
    MailHelperError,
    send_logiklu_otp_email,
    send_logiklu_password_reset_email,
)
from app.core.device_auth_security import (
    DeviceAuthSecurityError,
    generate_login_session_id,
    generate_otp,
    generate_otp_challenge_id,
    generate_refresh_token,
    get_device_trust_days,
    get_otp_expire_seconds,
    get_otp_max_attempts,
    get_otp_max_resends,
    get_otp_resend_cooldown_seconds,
    get_refresh_session_days,
    hash_otp,
    hash_refresh_token,
    issue_device_access_token,
    normalize_client_type,
    verify_otp_hash,
)
from app.db.master import get_master_connection
from app.services.mobile_auth_service import (
    determine_landing_page,
    fetch_domains_for_user,
    fetch_permission_group,
)


ROOT_URL = "https://logiklu.com/"


class DeviceAuthServiceError(Exception):
    def __init__(
        self,
        message: str,
        error_code: str,
        http_status: int = 400,
        data: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.http_status = http_status
        self.data = data or {}


def _utcnow() -> datetime:
    return datetime.utcnow()


def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _as_datetime(value: Any) -> Optional[datetime]:
    if value is None or value == "":
        return None

    if isinstance(value, datetime):
        return value

    text = str(value).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text[:19], fmt)
        except Exception:
            continue

    return None


def _is_active_user_status(value: Any) -> bool:
    return _safe_str(value).lower() in {"1", "active"}


def _verify_legacy_md5_password(password: str, stored_hash: Any) -> bool:
    """
    Existing LogiKlu password compatibility.

    The current device-login protocol does not write passwords; it only verifies
    the existing zp_users.password MD5 value. If an older record contains a
    colon suffix, only the MD5 portion before ':' is compared.
    """
    stored = _safe_str(stored_hash)
    if not stored:
        return False

    stored_md5 = stored.split(":", 1)[0].strip().lower()
    calculated = hashlib.md5(str(password or "").encode("utf-8")).hexdigest()
    return hmac.compare_digest(calculated.lower(), stored_md5)


def _full_name(user: Dict[str, Any]) -> str:
    return " ".join(
        part
        for part in [
            _safe_str(user.get("first_name")),
            _safe_str(user.get("last_name")),
        ]
        if part
    ).strip()


def _mask_email(email: str) -> str:
    email = _safe_str(email)
    if "@" not in email:
        return email

    local, domain = email.split("@", 1)
    if len(local) <= 2:
        masked = local[:1] + "*" * max(len(local) - 1, 1)
    elif len(local) == 3:
        masked = local[:1] + "*" + local[-1:]
    else:
        masked = local[:2] + "*" * (len(local) - 3) + local[-1:]

    return masked + "@" + domain


def _max_devices(user: Dict[str, Any]) -> int:
    value = user.get("maxdevicelogin")
    if value is None:
        return 2
    return max(_safe_int(value, 0), 0)


def _fetch_user_by_identifier(identifier: str) -> Optional[Dict[str, Any]]:
    connection = None
    try:
        connection = get_master_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT *
                FROM zp_users
                WHERE username = %s OR email = %s
                LIMIT 1
                """,
                (identifier, identifier),
            )
            return cursor.fetchone()
    finally:
        if connection:
            connection.close()


def _fetch_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    connection = None
    try:
        connection = get_master_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT * FROM zp_users WHERE id = %s LIMIT 1",
                (user_id,),
            )
            return cursor.fetchone()
    finally:
        if connection:
            connection.close()


def _fetch_access_group(user_id: int) -> Optional[Dict[str, Any]]:
    connection = None
    try:
        connection = get_master_connection()
        with connection.cursor() as cursor:
            return _fetch_access_group_with_cursor(cursor, user_id)
    finally:
        if connection:
            connection.close()


def _fetch_access_group_with_cursor(cursor, user_id: int) -> Optional[Dict[str, Any]]:
    cursor.execute(
        """
        SELECT
            b.id AS access_group_id,
            b.group_code,
            b.group_title,
            b.login_point
        FROM zp_access_group_user_association c
        INNER JOIN zp_access_group b
            ON b.id = c.group_id
        WHERE c.user_id = %s
          AND b.status = '1'
        ORDER BY b.id ASC
        LIMIT 1
        """,
        (user_id,),
    )
    return cursor.fetchone()


def _build_public_user(user: Dict[str, Any], group: Dict[str, Any]) -> Dict[str, Any]:
    profile_image = _safe_str(user.get("profile_image"))
    avatar_url = (
        ROOT_URL + "upload/avatar/" + profile_image
        if profile_image
        else ROOT_URL + "images/gravatar.jpg"
    )

    login_point = _safe_int(group.get("login_point"))

    return {
        "id": _safe_int(user.get("id")),
        "name": _full_name(user),
        "first_name": _safe_str(user.get("first_name")),
        "last_name": _safe_str(user.get("last_name")),
        "username": _safe_str(user.get("username")),
        "email": _safe_str(user.get("email")),
        "company": _safe_str(user.get("company")),
        "title": _safe_str(user.get("title")),
        "avatar_url": avatar_url,
        "user_role": "member" if login_point == 1 else "admin",
        "group": {
            "id": _safe_int(group.get("access_group_id")),
            "code": _safe_str(group.get("group_code")),
            "title": _safe_str(group.get("group_title")),
            "login_point": login_point,
        },
    }


def _build_account_context(
    user: Dict[str, Any],
    group: Dict[str, Any],
    current_timezone: str,
) -> Dict[str, Any]:
    user_id = _safe_int(user.get("id"))
    login_point = _safe_int(group.get("login_point"))
    raw_domains = fetch_domains_for_user(user_id, login_point)

    domains: List[Dict[str, Any]] = []
    landing_page_map: Dict[str, str] = {}

    for domain in raw_domains:
        client_database = _safe_str(domain.get("databasename"))
        domain_id = _safe_int(domain.get("domain_id"))

        if not client_database or domain_id <= 0:
            continue

        permission_group = fetch_permission_group(client_database, user_id)
        landing_page = determine_landing_page(
            client_database=client_database,
            user_id=user_id,
            permission_group=permission_group,
            login_point=login_point,
        )

        landing_page_map[str(domain_id)] = landing_page
        webkey = _safe_str(domain.get("webkey"))

        domains.append(
            {
                "domain_id": domain_id,
                "account_id": _safe_int(domain.get("ac_id")),
                "account_name": _safe_str(domain.get("account_name")),
                "website": _safe_str(domain.get("websitename")),
                "original_website": _safe_str(domain.get("originalwebsitename")),
                "webkey": webkey,
                "logo_url": (
                    ROOT_URL + "subscriber/" + webkey + "/logo/logo.png"
                    if webkey
                    else None
                ),
                "timezone": _safe_str(domain.get("timezone")),
                "permission_group": permission_group,
                "landing_page": landing_page,
            }
        )

    return {
        "user": _build_public_user(user, group),
        "assigned_domain": len(domains),
        "assigned_domains": domains,
        "landing_pages": landing_page_map,
        "landing_page": domains[0]["landing_page"] if domains else None,
        "current_timezone": _safe_str(current_timezone) or "UTC",
    }


def _count_other_active_devices(
    cursor,
    user_id: int,
    now: datetime,
    exclude_device_row_id: Optional[int] = None,
) -> int:
    sql = """
        SELECT COUNT(*) AS device_count
        FROM zp_user_login_device
        WHERE user_id = %s
          AND deviceexpiredate > %s
          AND status = 'active'
          AND loginstatus = 'loggedin'
    """
    params: List[Any] = [user_id, now]

    if exclude_device_row_id:
        sql += " AND id <> %s"
        params.append(exclude_device_row_id)

    cursor.execute(sql, tuple(params))
    row = cursor.fetchone() or {}
    return _safe_int(row.get("device_count"), 0)


def _assert_device_slot_available(
    cursor,
    user: Dict[str, Any],
    now: datetime,
    exclude_device_row_id: Optional[int] = None,
) -> None:
    maximum = _max_devices(user)
    active_count = _count_other_active_devices(
        cursor=cursor,
        user_id=_safe_int(user.get("id")),
        now=now,
        exclude_device_row_id=exclude_device_row_id,
    )

    if maximum <= 0 or active_count >= maximum:
        raise DeviceAuthServiceError(
            "Maximum device login limit has been reached. Please log out from another device to continue.",
            "AUTH_DEVICE_LIMIT_EXCEEDED",
            409,
            {
                "max_devices": maximum,
                "active_devices": active_count,
            },
        )


def _fetch_device_for_update(
    cursor,
    user_id: int,
    client_type: str,
    device_id: str,
) -> Optional[Dict[str, Any]]:
    cursor.execute(
        """
        SELECT *
        FROM zp_user_login_device
        WHERE user_id = %s
          AND device_source = %s
          AND device_id = %s
        LIMIT 1
        FOR UPDATE
        """,
        (user_id, client_type, device_id),
    )
    return cursor.fetchone()


def _is_trusted_device(device: Optional[Dict[str, Any]], now: datetime) -> bool:
    if not device:
        return False

    expires = _as_datetime(device.get("deviceexpiredate"))
    return (
        _safe_str(device.get("status")).lower() == "active"
        and _safe_str(device.get("loginstatus")).lower()
        in {"loggedin", "loggedout"}
        and expires is not None
        and expires > now
    )


def _create_session_with_cursor(
    cursor,
    user_id: int,
    client_type: str,
    device_id: str,
    client_ip: str,
    app_version: str,
    current_timezone: str,
    device_trusted_until: datetime,
    now: datetime,
) -> Dict[str, Any]:
    # One active API session per user/device. A manual re-login invalidates the
    # previous API session for the same device but does not remove device trust.
    cursor.execute(
        """
        UPDATE zp_user_login
        SET
            logout_time = COALESCE(logout_time, %s),
            revoked_date = COALESCE(revoked_date, %s),
            revoked_reason = 'relogin',
            session_status = 'revoked'
        WHERE user_id = %s
          AND login_source = %s
          AND device_id = %s
          AND session_status = 'active'
        """,
        (now, now, user_id, client_type, device_id),
    )

    refresh_token = generate_refresh_token()
    refresh_token_hash = hash_refresh_token(refresh_token)
    login_session = generate_login_session_id()

    proposed_refresh_expiry = now + timedelta(days=get_refresh_session_days())
    refresh_expires_date = min(proposed_refresh_expiry, device_trusted_until)

    cursor.execute(
        """
        INSERT INTO zp_user_login
        (
            user_id,
            login_source,
            lk_logincookie,
            device_id,
            login_session,
            refresh_token_hash,
            refresh_expires_date,
            last_used_date,
            refresh_rotated_date,
            revoked_date,
            revoked_reason,
            session_status,
            app_version,
            current_timezone,
            login_time,
            logout_time,
            ip
        )
        VALUES
        (
            %s, %s, NULL, %s, %s, %s, %s,
            %s, NULL, NULL, NULL, 'active', %s, %s,
            %s, NULL, %s
        )
        """,
        (
            user_id,
            client_type,
            device_id,
            login_session,
            refresh_token_hash,
            refresh_expires_date,
            now,
            _safe_str(app_version),
            _safe_str(current_timezone) or "UTC",
            now,
            client_ip,
        ),
    )

    return {
        "refresh_token": refresh_token,
        "refresh_expires_date": refresh_expires_date,
        "login_session": login_session,
        "login_id": _safe_int(cursor.lastrowid),
    }


def _complete_authenticated_response(
    user: Dict[str, Any],
    group: Dict[str, Any],
    session: Dict[str, Any],
    current_timezone: str,
    device_trusted_until: datetime,
) -> Dict[str, Any]:
    token = issue_device_access_token(
        user_id=_safe_int(user.get("id")),
        group_code=_safe_str(group.get("group_code")),
        login_point=_safe_int(group.get("login_point")),
    )

    account_context = _build_account_context(
        user=user,
        group=group,
        current_timezone=current_timezone,
    )

    return {
        "authentication_status": "authenticated",
        **token,
        "refresh_token": session["refresh_token"],
        "refresh_expires_date": session["refresh_expires_date"].isoformat() + "Z",
        "session_id": session["login_session"],
        "device_trusted_until": device_trusted_until.isoformat() + "Z",
        **account_context,
    }


def _upsert_pending_otp_device(
    cursor,
    existing_device: Optional[Dict[str, Any]],
    user: Dict[str, Any],
    client_type: str,
    device_id: str,
    device_name: str,
    device_os: str,
    os_version: str,
    app_version: str,
    current_timezone: str,
    client_ip: str,
    challenge_id: str,
    otp_value: str,
    otp_hash_value: str,
    now: datetime,
    expires: datetime,
) -> int:
    user_id = _safe_int(user.get("id"))

    if existing_device:
        cursor.execute(
            """
            UPDATE zp_user_login_device
            SET
                email = %s,
                phone = %s,
                ip = %s,
                device_name = %s,
                device_os = %s,
                os_version = %s,
                app_version = %s,
                current_timezone = %s,
                otp = %s,
                otp_hash = %s,
                otp_challenge_uid = %s,
                otp_attempt_count = 0,
                otp_resend_count = 0,
                otp_last_sent_date = %s,
                otptime = %s,
                otpexpiretime = %s,
                otpvalidateddate = NULL,
                deviceexpiredate = NULL,
                last_seen_date = %s,
                loginstatus = 'not',
                status = 'inactive'
            WHERE id = %s
            """,
            (
                _safe_str(user.get("email")),
                _safe_str(user.get("phone")),
                client_ip,
                device_name,
                device_os,
                os_version,
                app_version,
                current_timezone,
                otp_value,
                otp_hash_value,
                challenge_id,
                now,
                now,
                expires,
                now,
                _safe_int(existing_device.get("id")),
            ),
        )
        return _safe_int(existing_device.get("id"))

    cursor.execute(
        """
        INSERT INTO zp_user_login_device
        (
            user_id,
            device_source,
            email,
            phone,
            ip,
            lk_logincookie,
            device_id,
            device_name,
            device_os,
            os_version,
            app_version,
            current_timezone,
            otp,
            otp_hash,
            otp_challenge_uid,
            otp_attempt_count,
            otp_resend_count,
            otp_last_sent_date,
            otptime,
            otpexpiretime,
            otpvalidateddate,
            deviceadddate,
            deviceexpiredate,
            last_seen_date,
            loginstatus,
            status
        )
        VALUES
        (
            %s, %s, %s, %s, %s, NULL, %s, %s, %s, %s, %s, %s,
            %s, %s, %s, 0, 0, %s, %s, %s, NULL, %s, NULL, %s,
            'not', 'inactive'
        )
        """,
        (
            user_id,
            client_type,
            _safe_str(user.get("email")),
            _safe_str(user.get("phone")),
            client_ip,
            device_id,
            device_name,
            device_os,
            os_version,
            app_version,
            current_timezone,
            otp_value,
            otp_hash_value,
            challenge_id,
            now,
            now,
            expires,
            now,
            now,
        ),
    )
    return _safe_int(cursor.lastrowid)


def device_login(
    username: str,
    password: str,
    client_type: str,
    device_id: str,
    device_name: str,
    device_os: str,
    os_version: str,
    app_version: str,
    current_timezone: str,
    client_ip: str,
) -> Dict[str, Any]:
    username = _safe_str(username)
    password = str(password or "")
    device_id = _safe_str(device_id)
    current_timezone = _safe_str(current_timezone) or "UTC"

    if not username:
        raise DeviceAuthServiceError(
            "Username / Email is required",
            "AUTH_USERNAME_REQUIRED",
            422,
        )

    if not password:
        raise DeviceAuthServiceError(
            "Password is required",
            "AUTH_PASSWORD_REQUIRED",
            422,
        )

    if not device_id:
        raise DeviceAuthServiceError(
            "Device ID is required",
            "AUTH_DEVICE_ID_REQUIRED",
            422,
        )

    try:
        client_type = normalize_client_type(client_type)
    except DeviceAuthSecurityError as exc:
        raise DeviceAuthServiceError(
            str(exc),
            "AUTH_CLIENT_TYPE_INVALID",
            422,
        ) from exc

    user = _fetch_user_by_identifier(username)

    if not user:
        raise DeviceAuthServiceError(
            "Username / Email does not exist",
            "AUTH_USER_NOT_FOUND",
            404,
        )

    if not _is_active_user_status(user.get("status")):
        raise DeviceAuthServiceError(
            "This user is not active. Please contact Administrator",
            "AUTH_USER_INACTIVE",
            403,
        )

    if not _verify_legacy_md5_password(password, user.get("password")):
        raise DeviceAuthServiceError(
            "Password does not match",
            "AUTH_PASSWORD_MISMATCH",
            401,
        )

    user_id = _safe_int(user.get("id"))
    group = _fetch_access_group(user_id)

    if not group:
        raise DeviceAuthServiceError(
            "No active access group is assigned to this user",
            "AUTH_ACCESS_GROUP_MISSING",
            403,
        )

    now = _utcnow()
    connection = None
    otp_to_send: Optional[str] = None
    pending_response: Optional[Dict[str, Any]] = None
    authenticated_session: Optional[Dict[str, Any]] = None
    device_trusted_until: Optional[datetime] = None

    try:
        connection = get_master_connection()
        connection.begin()

        with connection.cursor() as cursor:
            # Lock the user while checking maxdevicelogin to avoid simultaneous
            # logins racing past the configured device limit.
            cursor.execute(
                "SELECT * FROM zp_users WHERE id = %s LIMIT 1 FOR UPDATE",
                (user_id,),
            )
            locked_user = cursor.fetchone()

            if not locked_user or not _is_active_user_status(locked_user.get("status")):
                raise DeviceAuthServiceError(
                    "This user is not active. Please contact Administrator",
                    "AUTH_USER_INACTIVE",
                    403,
                )

            device = _fetch_device_for_update(
                cursor=cursor,
                user_id=user_id,
                client_type=client_type,
                device_id=device_id,
            )

            if _is_trusted_device(device, now):
                _assert_device_slot_available(
                    cursor=cursor,
                    user=locked_user,
                    now=now,
                    exclude_device_row_id=_safe_int(device.get("id")),
                )

                device_trusted_until = _as_datetime(device.get("deviceexpiredate"))
                authenticated_session = _create_session_with_cursor(
                    cursor=cursor,
                    user_id=user_id,
                    client_type=client_type,
                    device_id=device_id,
                    client_ip=client_ip,
                    app_version=app_version,
                    current_timezone=current_timezone,
                    device_trusted_until=device_trusted_until,
                    now=now,
                )

                cursor.execute(
                    """
                    UPDATE zp_user_login_device
                    SET
                        loginstatus = 'loggedin',
                        ip = %s,
                        device_name = %s,
                        device_os = %s,
                        os_version = %s,
                        app_version = %s,
                        current_timezone = %s,
                        last_seen_date = %s
                    WHERE id = %s
                    """,
                    (
                        client_ip,
                        _safe_str(device_name),
                        _safe_str(device_os),
                        _safe_str(os_version),
                        _safe_str(app_version),
                        current_timezone,
                        now,
                        _safe_int(device.get("id")),
                    ),
                )

            else:
                _assert_device_slot_available(
                    cursor=cursor,
                    user=locked_user,
                    now=now,
                )

                otp_to_send = generate_otp()
                challenge_id = generate_otp_challenge_id()
                otp_expiry = now + timedelta(seconds=get_otp_expire_seconds())
                otp_hash_value = hash_otp(
                    otp=otp_to_send,
                    challenge_id=challenge_id,
                    device_id=device_id,
                )

                _upsert_pending_otp_device(
                    cursor=cursor,
                    existing_device=device,
                    user=locked_user,
                    client_type=client_type,
                    device_id=device_id,
                    device_name=_safe_str(device_name),
                    device_os=_safe_str(device_os),
                    os_version=_safe_str(os_version),
                    app_version=_safe_str(app_version),
                    current_timezone=current_timezone,
                    client_ip=client_ip,
                    challenge_id=challenge_id,
                    otp_value=otp_to_send,
                    otp_hash_value=otp_hash_value,
                    now=now,
                    expires=otp_expiry,
                )

                pending_response = {
                    "authentication_status": "otp_required",
                    "challenge_id": challenge_id,
                    "otp_expires_in": get_otp_expire_seconds(),
                    "resend_available_in": get_otp_resend_cooldown_seconds(),
                    "masked_email": _mask_email(_safe_str(locked_user.get("email"))),
                }

        connection.commit()

    except DeviceAuthServiceError:
        if connection:
            try:
                connection.rollback()
            except Exception:
                pass
        raise
    except Exception as exc:
        if connection:
            try:
                connection.rollback()
            except Exception:
                pass
        raise DeviceAuthServiceError(
            "Unable to process device login",
            "AUTH_LOGIN_PROCESS_FAILED",
            500,
            {"error": str(exc)},
        ) from exc
    finally:
        if connection:
            connection.close()

    if pending_response is not None and otp_to_send is not None:
        try:
            mail_result = send_logiklu_otp_email(
                recipient_name=_full_name(user),
                recipient_email=_safe_str(user.get("email")),
                otp=otp_to_send,
            )
            if _safe_str(mail_result.get("status")).lower() == "error":
                raise MailHelperError("Mail service rejected OTP email")
        except Exception as exc:
            raise DeviceAuthServiceError(
                "OTP was generated but the email could not be sent. Please try Resend OTP.",
                "AUTH_OTP_EMAIL_FAILED",
                502,
                {
                    "challenge_id": pending_response["challenge_id"],
                    "otp_expires_in": pending_response["otp_expires_in"],
                    "resend_available_in": pending_response["resend_available_in"],
                },
            ) from exc

        return {
            "message": "OTP has been sent to your registered email address",
            "data": pending_response,
        }

    if authenticated_session is None or device_trusted_until is None:
        raise DeviceAuthServiceError(
            "Unable to complete login",
            "AUTH_LOGIN_PROCESS_FAILED",
            500,
        )

    return {
        "message": "Login successful",
        "data": _complete_authenticated_response(
            user=user,
            group=group,
            session=authenticated_session,
            current_timezone=current_timezone,
            device_trusted_until=device_trusted_until,
        ),
    }


def verify_device_otp(
    challenge_id: str,
    otp: str,
    device_id: str,
    client_ip: str,
) -> Dict[str, Any]:
    challenge_id = _safe_str(challenge_id)
    otp = _safe_str(otp)
    device_id = _safe_str(device_id)

    if not otp.isdigit() or len(otp) != 6:
        raise DeviceAuthServiceError(
            "The OTP you entered is invalid",
            "AUTH_OTP_INVALID",
            400,
        )

    now = _utcnow()
    connection = None
    user: Optional[Dict[str, Any]] = None
    group: Optional[Dict[str, Any]] = None
    session: Optional[Dict[str, Any]] = None
    trusted_until: Optional[datetime] = None
    current_timezone = "UTC"
    pending_error: Optional[DeviceAuthServiceError] = None

    try:
        connection = get_master_connection()
        connection.begin()

        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT *
                FROM zp_user_login_device
                WHERE otp_challenge_uid = %s
                  AND device_id = %s
                  AND loginstatus = 'not'
                LIMIT 1
                FOR UPDATE
                """,
                (challenge_id, device_id),
            )
            device = cursor.fetchone()

            if not device:
                raise DeviceAuthServiceError(
                    "Invalid login verification request",
                    "AUTH_OTP_CHALLENGE_INVALID",
                    400,
                )

            max_attempts = get_otp_max_attempts()
            current_attempts = _safe_int(device.get("otp_attempt_count"), 0)

            if current_attempts >= max_attempts or not _safe_str(device.get("otp_hash")):
                raise DeviceAuthServiceError(
                    "Maximum OTP verification attempts exceeded. Please request a new OTP.",
                    "AUTH_OTP_ATTEMPTS_EXCEEDED",
                    429,
                )

            otp_expiry = _as_datetime(device.get("otpexpiretime"))
            if otp_expiry is None or otp_expiry <= now:
                raise DeviceAuthServiceError(
                    "OTP has expired. Please request a new OTP.",
                    "AUTH_OTP_EXPIRED",
                    410,
                )

            if not verify_otp_hash(
                submitted_otp=otp,
                challenge_id=challenge_id,
                device_id=device_id,
                stored_hash=_safe_str(device.get("otp_hash")),
            ):
                new_attempts = current_attempts + 1
                clear_hash = new_attempts >= max_attempts

                cursor.execute(
                    """
                    UPDATE zp_user_login_device
                    SET
                        otp_attempt_count = %s,
                        otp = CASE WHEN %s = 1 THEN NULL ELSE otp END,
                        otp_hash = CASE WHEN %s = 1 THEN NULL ELSE otp_hash END
                    WHERE id = %s
                    """,
                    (
                        new_attempts,
                        1 if clear_hash else 0,
                        1 if clear_hash else 0,
                        _safe_int(device.get("id")),
                    ),
                )

                remaining = max(max_attempts - new_attempts, 0)
                if clear_hash:
                    pending_error = DeviceAuthServiceError(
                        "Maximum OTP verification attempts exceeded. Please request a new OTP.",
                        "AUTH_OTP_ATTEMPTS_EXCEEDED",
                        429,
                        {"attempts_remaining": 0},
                    )
                else:
                    pending_error = DeviceAuthServiceError(
                        "The OTP you entered is invalid",
                        "AUTH_OTP_INVALID",
                        400,
                        {"attempts_remaining": remaining},
                    )
            else:
                user_id = _safe_int(device.get("user_id"))
                cursor.execute(
                    "SELECT * FROM zp_users WHERE id = %s LIMIT 1 FOR UPDATE",
                    (user_id,),
                )
                user = cursor.fetchone()

                if not user:
                    raise DeviceAuthServiceError(
                        "Username / Email does not exist",
                        "AUTH_USER_NOT_FOUND",
                        404,
                    )

                if not _is_active_user_status(user.get("status")):
                    raise DeviceAuthServiceError(
                        "This user is not active. Please contact Administrator",
                        "AUTH_USER_INACTIVE",
                        403,
                    )

                group = _fetch_access_group_with_cursor(cursor, user_id)
                if not group:
                    raise DeviceAuthServiceError(
                        "No active access group is assigned to this user",
                        "AUTH_ACCESS_GROUP_MISSING",
                        403,
                    )

                _assert_device_slot_available(
                    cursor=cursor,
                    user=user,
                    now=now,
                    exclude_device_row_id=_safe_int(device.get("id")),
                )

                trusted_until = now + timedelta(days=get_device_trust_days())
                client_type = _safe_str(device.get("device_source")) or "mobile"
                current_timezone = _safe_str(device.get("current_timezone")) or "UTC"

                cursor.execute(
                    """
                    UPDATE zp_user_login_device
                    SET
                        otp = NULL,
                        otp_hash = NULL,
                        otp_challenge_uid = NULL,
                        otp_attempt_count = 0,
                        otpvalidateddate = %s,
                        deviceexpiredate = %s,
                        loginstatus = 'loggedin',
                        status = 'active',
                        ip = %s,
                        last_seen_date = %s
                    WHERE id = %s
                    """,
                    (
                        now,
                        trusted_until,
                        client_ip,
                        now,
                        _safe_int(device.get("id")),
                    ),
                )

                session = _create_session_with_cursor(
                    cursor=cursor,
                    user_id=user_id,
                    client_type=client_type,
                    device_id=device_id,
                    client_ip=client_ip,
                    app_version=_safe_str(device.get("app_version")),
                    current_timezone=current_timezone,
                    device_trusted_until=trusted_until,
                    now=now,
                )

        connection.commit()

    except DeviceAuthServiceError:
        if connection:
            try:
                connection.rollback()
            except Exception:
                pass
        raise
    except Exception as exc:
        if connection:
            try:
                connection.rollback()
            except Exception:
                pass
        raise DeviceAuthServiceError(
            "Unable to verify OTP",
            "AUTH_OTP_VERIFY_FAILED",
            500,
            {"error": str(exc)},
        ) from exc
    finally:
        if connection:
            connection.close()

    if pending_error is not None:
        raise pending_error

    if not user or not group or not session or not trusted_until:
        raise DeviceAuthServiceError(
            "Unable to complete OTP verification",
            "AUTH_OTP_VERIFY_FAILED",
            500,
        )

    return {
        "message": "OTP verified successfully",
        "data": _complete_authenticated_response(
            user=user,
            group=group,
            session=session,
            current_timezone=current_timezone,
            device_trusted_until=trusted_until,
        ),
    }


def resend_device_otp(
    challenge_id: str,
    device_id: str,
    client_ip: str,
) -> Dict[str, Any]:
    challenge_id = _safe_str(challenge_id)
    device_id = _safe_str(device_id)
    now = _utcnow()
    connection = None
    otp_to_send: Optional[str] = None
    user: Optional[Dict[str, Any]] = None
    response_data: Optional[Dict[str, Any]] = None

    try:
        connection = get_master_connection()
        connection.begin()

        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT *
                FROM zp_user_login_device
                WHERE otp_challenge_uid = %s
                  AND device_id = %s
                  AND loginstatus = 'not'
                LIMIT 1
                FOR UPDATE
                """,
                (challenge_id, device_id),
            )
            device = cursor.fetchone()

            if not device:
                raise DeviceAuthServiceError(
                    "Invalid login verification request",
                    "AUTH_OTP_CHALLENGE_INVALID",
                    400,
                )

            current_resends = _safe_int(device.get("otp_resend_count"), 0)
            max_resends = get_otp_max_resends()

            if current_resends >= max_resends:
                cursor.execute(
                    """
                    UPDATE zp_user_login_device
                    SET otp = NULL, otp_hash = NULL, otp_challenge_uid = NULL
                    WHERE id = %s
                    """,
                    (_safe_int(device.get("id")),),
                )
                connection.commit()
                raise DeviceAuthServiceError(
                    "Maximum OTP resend attempts exceeded. Please start the login process again.",
                    "AUTH_OTP_RESEND_LIMIT_EXCEEDED",
                    429,
                )

            last_sent = _as_datetime(device.get("otp_last_sent_date")) or _as_datetime(
                device.get("otptime")
            )
            cooldown = get_otp_resend_cooldown_seconds()

            if last_sent is not None:
                elapsed = int((now - last_sent).total_seconds())
                if elapsed < cooldown:
                    raise DeviceAuthServiceError(
                        "Please wait before requesting another OTP",
                        "AUTH_OTP_RESEND_TOO_SOON",
                        429,
                        {"retry_after": max(cooldown - elapsed, 1)},
                    )

            user_id = _safe_int(device.get("user_id"))
            cursor.execute(
                "SELECT * FROM zp_users WHERE id = %s LIMIT 1 FOR UPDATE",
                (user_id,),
            )
            user = cursor.fetchone()

            if not user:
                raise DeviceAuthServiceError(
                    "Username / Email does not exist",
                    "AUTH_USER_NOT_FOUND",
                    404,
                )

            if not _is_active_user_status(user.get("status")):
                raise DeviceAuthServiceError(
                    "This user is not active. Please contact Administrator",
                    "AUTH_USER_INACTIVE",
                    403,
                )

            _assert_device_slot_available(
                cursor=cursor,
                user=user,
                now=now,
                exclude_device_row_id=_safe_int(device.get("id")),
            )

            otp_to_send = generate_otp()
            otp_expiry = now + timedelta(seconds=get_otp_expire_seconds())
            otp_hash_value = hash_otp(
                otp=otp_to_send,
                challenge_id=challenge_id,
                device_id=device_id,
            )
            new_resend_count = current_resends + 1

            cursor.execute(
                """
                UPDATE zp_user_login_device
                SET
                    otp = %s,
                    otp_hash = %s,
                    otp_attempt_count = 0,
                    otp_resend_count = %s,
                    otp_last_sent_date = %s,
                    otptime = %s,
                    otpexpiretime = %s,
                    ip = %s,
                    last_seen_date = %s
                WHERE id = %s
                """,
                (
                    otp_to_send,
                    otp_hash_value,
                    new_resend_count,
                    now,
                    now,
                    otp_expiry,
                    client_ip,
                    now,
                    _safe_int(device.get("id")),
                ),
            )

            response_data = {
                "authentication_status": "otp_required",
                "challenge_id": challenge_id,
                "otp_expires_in": get_otp_expire_seconds(),
                "resend_available_in": cooldown,
                "resend_count": new_resend_count,
                "masked_email": _mask_email(_safe_str(user.get("email"))),
            }

        connection.commit()

    except DeviceAuthServiceError:
        if connection:
            try:
                connection.rollback()
            except Exception:
                pass
        raise
    except Exception as exc:
        if connection:
            try:
                connection.rollback()
            except Exception:
                pass
        raise DeviceAuthServiceError(
            "Unable to resend OTP",
            "AUTH_OTP_RESEND_FAILED",
            500,
            {"error": str(exc)},
        ) from exc
    finally:
        if connection:
            connection.close()

    if not otp_to_send or not user or response_data is None:
        raise DeviceAuthServiceError(
            "Unable to resend OTP",
            "AUTH_OTP_RESEND_FAILED",
            500,
        )

    try:
        mail_result = send_logiklu_otp_email(
            recipient_name=_full_name(user),
            recipient_email=_safe_str(user.get("email")),
            otp=otp_to_send,
        )
        if _safe_str(mail_result.get("status")).lower() == "error":
            raise MailHelperError("Mail service rejected OTP email")
    except Exception as exc:
        raise DeviceAuthServiceError(
            "OTP was regenerated but the email could not be sent. Please try again.",
            "AUTH_OTP_EMAIL_FAILED",
            502,
            response_data,
        ) from exc

    return {
        "message": "OTP has been resent to your registered email address",
        "data": response_data,
    }


def restore_device_session(
    refresh_token: str,
    device_id: str,
    app_version: str,
    current_timezone: str,
    client_ip: str,
) -> Dict[str, Any]:
    refresh_token = _safe_str(refresh_token)
    device_id = _safe_str(device_id)
    current_timezone = _safe_str(current_timezone) or "UTC"
    token_hash = hash_refresh_token(refresh_token)
    now = _utcnow()

    connection = None
    user: Optional[Dict[str, Any]] = None
    group: Optional[Dict[str, Any]] = None
    new_session_data: Optional[Dict[str, Any]] = None
    trusted_until: Optional[datetime] = None

    try:
        connection = get_master_connection()
        connection.begin()

        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT *
                FROM zp_user_login
                WHERE refresh_token_hash = %s
                  AND login_source IN ('web','mobile','tablet')
                LIMIT 1
                FOR UPDATE
                """,
                (token_hash,),
            )
            login_row = cursor.fetchone()

            if not login_row:
                raise DeviceAuthServiceError(
                    "Session is invalid or has already been rotated. Please sign in again.",
                    "AUTH_SESSION_INVALID",
                    401,
                )

            if _safe_str(login_row.get("device_id")) != device_id:
                raise DeviceAuthServiceError(
                    "Session does not belong to this device.",
                    "AUTH_DEVICE_MISMATCH",
                    401,
                )

            session_status = _safe_str(login_row.get("session_status")).lower()
            if session_status == "revoked" or login_row.get("revoked_date") is not None:
                raise DeviceAuthServiceError(
                    "This session is no longer active. Please sign in again.",
                    "AUTH_SESSION_REVOKED",
                    401,
                )

            refresh_expiry = _as_datetime(login_row.get("refresh_expires_date"))
            if session_status == "expired" or refresh_expiry is None or refresh_expiry <= now:
                cursor.execute(
                    """
                    UPDATE zp_user_login
                    SET
                        session_status = 'expired',
                        logout_time = COALESCE(logout_time, %s)
                    WHERE id = %s
                    """,
                    (now, _safe_int(login_row.get("id"))),
                )
                connection.commit()
                raise DeviceAuthServiceError(
                    "Your session has expired. Please sign in again.",
                    "AUTH_SESSION_EXPIRED",
                    401,
                )

            user_id = _safe_int(login_row.get("user_id"))
            cursor.execute(
                "SELECT * FROM zp_users WHERE id = %s LIMIT 1 FOR UPDATE",
                (user_id,),
            )
            user = cursor.fetchone()

            if not user or not _is_active_user_status(user.get("status")):
                cursor.execute(
                    """
                    UPDATE zp_user_login
                    SET
                        session_status = 'revoked',
                        revoked_date = %s,
                        revoked_reason = 'user_inactive',
                        logout_time = COALESCE(logout_time, %s)
                    WHERE id = %s
                    """,
                    (now, now, _safe_int(login_row.get("id"))),
                )
                connection.commit()
                raise DeviceAuthServiceError(
                    "This user is not active. Please contact Administrator",
                    "AUTH_USER_INACTIVE",
                    403,
                )

            group = _fetch_access_group_with_cursor(cursor, user_id)
            if not group:
                raise DeviceAuthServiceError(
                    "No active access group is assigned to this user",
                    "AUTH_ACCESS_GROUP_MISSING",
                    403,
                )

            client_type = _safe_str(login_row.get("login_source")) or "mobile"
            device = _fetch_device_for_update(
                cursor=cursor,
                user_id=user_id,
                client_type=client_type,
                device_id=device_id,
            )

            trusted_until = _as_datetime((device or {}).get("deviceexpiredate"))
            trusted = (
                device is not None
                and _safe_str(device.get("status")).lower() == "active"
                and _safe_str(device.get("loginstatus")).lower() == "loggedin"
                and trusted_until is not None
                and trusted_until > now
            )

            if not trusted:
                cursor.execute(
                    """
                    UPDATE zp_user_login
                    SET
                        session_status = 'revoked',
                        revoked_date = %s,
                        revoked_reason = 'device_trust_expired',
                        logout_time = COALESCE(logout_time, %s)
                    WHERE id = %s
                    """,
                    (now, now, _safe_int(login_row.get("id"))),
                )

                if device is not None and (
                    trusted_until is None or trusted_until <= now
                ):
                    cursor.execute(
                        """
                        UPDATE zp_user_login_device
                        SET loginstatus = 'not', status = 'inactive'
                        WHERE id = %s
                        """,
                        (_safe_int(device.get("id")),),
                    )

                connection.commit()
                raise DeviceAuthServiceError(
                    "Device verification has expired. Please sign in again.",
                    "AUTH_DEVICE_TRUST_EXPIRED",
                    401,
                )

            new_refresh_token = generate_refresh_token()
            new_refresh_hash = hash_refresh_token(new_refresh_token)
            new_refresh_expiry = min(
                now + timedelta(days=get_refresh_session_days()),
                trusted_until,
            )

            cursor.execute(
                """
                UPDATE zp_user_login
                SET
                    refresh_token_hash = %s,
                    refresh_expires_date = %s,
                    last_used_date = %s,
                    refresh_rotated_date = %s,
                    app_version = %s,
                    current_timezone = %s,
                    ip = %s
                WHERE id = %s
                """,
                (
                    new_refresh_hash,
                    new_refresh_expiry,
                    now,
                    now,
                    _safe_str(app_version),
                    current_timezone,
                    client_ip,
                    _safe_int(login_row.get("id")),
                ),
            )

            cursor.execute(
                """
                UPDATE zp_user_login_device
                SET
                    last_seen_date = %s,
                    app_version = %s,
                    current_timezone = %s,
                    ip = %s
                WHERE id = %s
                """,
                (
                    now,
                    _safe_str(app_version),
                    current_timezone,
                    client_ip,
                    _safe_int(device.get("id")),
                ),
            )

            new_session_data = {
                "refresh_token": new_refresh_token,
                "refresh_expires_date": new_refresh_expiry,
                "login_session": _safe_str(login_row.get("login_session")),
                "login_id": _safe_int(login_row.get("id")),
            }

        connection.commit()

    except DeviceAuthServiceError:
        if connection:
            try:
                connection.rollback()
            except Exception:
                pass
        raise
    except Exception as exc:
        if connection:
            try:
                connection.rollback()
            except Exception:
                pass
        raise DeviceAuthServiceError(
            "Unable to restore session",
            "AUTH_SESSION_RESTORE_FAILED",
            500,
            {"error": str(exc)},
        ) from exc
    finally:
        if connection:
            connection.close()

    if not user or not group or not new_session_data or not trusted_until:
        raise DeviceAuthServiceError(
            "Unable to restore session",
            "AUTH_SESSION_RESTORE_FAILED",
            500,
        )

    return {
        "message": "Session restored successfully",
        "data": _complete_authenticated_response(
            user=user,
            group=group,
            session=new_session_data,
            current_timezone=current_timezone,
            device_trusted_until=trusted_until,
        ),
    }


def logout_device_session(
    refresh_token: str,
    device_id: str,
) -> Dict[str, Any]:
    token_hash = hash_refresh_token(_safe_str(refresh_token))
    device_id = _safe_str(device_id)
    now = _utcnow()
    connection = None

    try:
        connection = get_master_connection()
        connection.begin()

        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT *
                FROM zp_user_login
                WHERE refresh_token_hash = %s
                LIMIT 1
                FOR UPDATE
                """,
                (token_hash,),
            )
            login_row = cursor.fetchone()

            if not login_row:
                connection.commit()
                return {
                    "message": "Session is already inactive",
                    "data": {"authentication_status": "logged_out"},
                }

            if _safe_str(login_row.get("device_id")) != device_id:
                raise DeviceAuthServiceError(
                    "Session does not belong to this device.",
                    "AUTH_DEVICE_MISMATCH",
                    401,
                )

            user_id = _safe_int(login_row.get("user_id"))
            client_type = _safe_str(login_row.get("login_source")) or "mobile"
            login_id = _safe_int(login_row.get("id"))
            already_inactive = _safe_str(login_row.get("session_status")).lower() != "active"

            if not already_inactive:
                cursor.execute(
                    """
                    UPDATE zp_user_login
                    SET
                        logout_time = COALESCE(logout_time, %s),
                        revoked_date = COALESCE(revoked_date, %s),
                        revoked_reason = 'logout',
                        session_status = 'revoked'
                    WHERE id = %s
                    """,
                    (now, now, login_id),
                )

            cursor.execute(
                """
                SELECT COUNT(*) AS active_sessions
                FROM zp_user_login
                WHERE user_id = %s
                  AND login_source = %s
                  AND device_id = %s
                  AND session_status = 'active'
                  AND id <> %s
                """,
                (user_id, client_type, device_id, login_id),
            )
            active_sessions = _safe_int(
                (cursor.fetchone() or {}).get("active_sessions"),
                0,
            )

            if active_sessions == 0:
                cursor.execute(
                    """
                    UPDATE zp_user_login_device
                    SET loginstatus = 'loggedout', last_seen_date = %s
                    WHERE user_id = %s
                      AND device_source = %s
                      AND device_id = %s
                      AND status = 'active'
                    """,
                    (now, user_id, client_type, device_id),
                )

        connection.commit()

    except DeviceAuthServiceError:
        if connection:
            try:
                connection.rollback()
            except Exception:
                pass
        raise
    except Exception as exc:
        if connection:
            try:
                connection.rollback()
            except Exception:
                pass
        raise DeviceAuthServiceError(
            "Unable to log out",
            "AUTH_LOGOUT_FAILED",
            500,
            {"error": str(exc)},
        ) from exc
    finally:
        if connection:
            connection.close()

    return {
        "message": "Session is already logged out" if already_inactive else "Logged out successfully",
        "data": {"authentication_status": "logged_out"},
    }


def _build_password_reset_link(user_id: int, token: str) -> str:
    template = _safe_str(
        os.getenv("LOGIKLU_PASSWORD_RESET_URL_TEMPLATE")
    ) or "https://logiklu.com/member/resetpassword/{user_id}/{token}"

    try:
        return template.format(
            user_id=user_id,
            token=quote(token, safe=""),
        )
    except Exception as exc:
        raise DeviceAuthServiceError(
            "Password reset URL is not configured correctly",
            "AUTH_PASSWORD_RESET_URL_INVALID",
            500,
        ) from exc


def forgot_device_password(username: str) -> Dict[str, Any]:
    username = _safe_str(username)

    if not username:
        raise DeviceAuthServiceError(
            "Username / Email is required",
            "AUTH_USERNAME_REQUIRED",
            422,
        )

    user = _fetch_user_by_identifier(username)

    if not user:
        raise DeviceAuthServiceError(
            "Username / Email does not exist",
            "AUTH_USER_NOT_FOUND",
            404,
        )

    if not _is_active_user_status(user.get("status")):
        raise DeviceAuthServiceError(
            "This user is not active. Please contact Administrator",
            "AUTH_USER_INACTIVE",
            403,
        )

    email = _safe_str(user.get("email"))
    if not email:
        raise DeviceAuthServiceError(
            "No registered email address is available for this user",
            "AUTH_USER_EMAIL_MISSING",
            422,
        )

    reset_token = secrets.token_urlsafe(48)
    expires_on = (_utcnow() + timedelta(hours=48)).date()
    user_id = _safe_int(user.get("id"))
    connection = None

    try:
        connection = get_master_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE zp_users
                SET
                    PasswordToken = %s,
                    PasswordTokenDate = %s,
                    PasswordTokenUse = 0
                WHERE id = %s
                """,
                (reset_token, expires_on, user_id),
            )
        connection.commit()
    except Exception as exc:
        if connection:
            try:
                connection.rollback()
            except Exception:
                pass
        raise DeviceAuthServiceError(
            "Unable to create password reset request",
            "AUTH_PASSWORD_RESET_CREATE_FAILED",
            500,
            {"error": str(exc)},
        ) from exc
    finally:
        if connection:
            connection.close()

    reset_link = _build_password_reset_link(user_id, reset_token)

    try:
        mail_result = send_logiklu_password_reset_email(
            recipient_name=_full_name(user),
            recipient_email=email,
            reset_link=reset_link,
        )
        if _safe_str(mail_result.get("status")).lower() == "error":
            raise MailHelperError("Mail service rejected password reset email")
    except Exception as exc:
        raise DeviceAuthServiceError(
            "Password reset request was created but the email could not be sent. Please try again.",
            "AUTH_PASSWORD_RESET_EMAIL_FAILED",
            502,
        ) from exc

    return {
        "message": "Password reset link has been sent to your registered email address successfully.",
        "data": {
            "masked_email": _mask_email(email),
            "expires_in": 172800,
        },
    }
