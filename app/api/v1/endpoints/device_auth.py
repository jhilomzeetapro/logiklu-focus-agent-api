from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.core.response import (
    current_utc_datetime,
    error_response,
    success_response,
)
from app.core.security import get_api_environment, get_client_ip
from app.schemas.device_auth import (
    DeviceForgotPasswordRequest,
    DeviceLoginRequest,
    DeviceLogoutRequest,
    DeviceOtpResendRequest,
    DeviceOtpVerifyRequest,
    DeviceSessionRestoreRequest,
)
from app.services.device_auth_service import (
    DeviceAuthServiceError,
    device_login,
    forgot_device_password,
    logout_device_session,
    resend_device_otp,
    restore_device_session,
    verify_device_otp,
)


router = APIRouter()


def _meta(authentication_status: str = ""):
    meta = {
        "generated_at": current_utc_datetime(),
        "mode": "device_auth",
        "environment": get_api_environment(),
        "schema_version": "logiklu_device_auth.v1",
    }

    if authentication_status:
        meta["authentication_status"] = authentication_status

    return meta


def _service_error_response(exc: DeviceAuthServiceError) -> JSONResponse:
    data = dict(exc.data or {})
    data["timestamp"] = current_utc_datetime()

    return JSONResponse(
        status_code=exc.http_status,
        content=error_response(
            message=exc.message,
            error_code=exc.error_code,
            data=data,
        ),
    )


def _unhandled_error(message: str, error_code: str, exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=500,
        content=error_response(
            message=message,
            error_code=error_code,
            data={
                "error": str(exc),
                "timestamp": current_utc_datetime(),
            },
        ),
    )


@router.post("/device/login")
def login(payload: DeviceLoginRequest, request: Request):
    try:
        result = device_login(
            username=payload.username,
            password=payload.password,
            client_type=payload.client_type,
            device_id=payload.device_id,
            device_name=payload.device_name or "",
            device_os=payload.device_os or "",
            os_version=payload.os_version or "",
            app_version=payload.app_version or "",
            current_timezone=payload.current_timezone or "UTC",
            client_ip=get_client_ip(request),
        )

        auth_status = str(result.get("data", {}).get("authentication_status") or "")

        return success_response(
            message=result["message"],
            meta=_meta(auth_status),
            data=result["data"],
        )

    except DeviceAuthServiceError as exc:
        return _service_error_response(exc)
    except Exception as exc:
        return _unhandled_error(
            "Login failed",
            "AUTH_LOGIN_FAILED",
            exc,
        )


@router.post("/device/otp/verify")
def otp_verify(payload: DeviceOtpVerifyRequest, request: Request):
    try:
        result = verify_device_otp(
            challenge_id=payload.challenge_id,
            otp=payload.otp,
            device_id=payload.device_id,
            client_ip=get_client_ip(request),
        )

        return success_response(
            message=result["message"],
            meta=_meta("authenticated"),
            data=result["data"],
        )

    except DeviceAuthServiceError as exc:
        return _service_error_response(exc)
    except Exception as exc:
        return _unhandled_error(
            "OTP verification failed",
            "AUTH_OTP_VERIFY_FAILED",
            exc,
        )


@router.post("/device/otp/resend")
def otp_resend(payload: DeviceOtpResendRequest, request: Request):
    try:
        result = resend_device_otp(
            challenge_id=payload.challenge_id,
            device_id=payload.device_id,
            client_ip=get_client_ip(request),
        )

        return success_response(
            message=result["message"],
            meta=_meta("otp_required"),
            data=result["data"],
        )

    except DeviceAuthServiceError as exc:
        return _service_error_response(exc)
    except Exception as exc:
        return _unhandled_error(
            "OTP resend failed",
            "AUTH_OTP_RESEND_FAILED",
            exc,
        )


@router.post("/device/session/restore")
def session_restore(payload: DeviceSessionRestoreRequest, request: Request):
    try:
        result = restore_device_session(
            refresh_token=payload.refresh_token,
            device_id=payload.device_id,
            app_version=payload.app_version or "",
            current_timezone=payload.current_timezone or "UTC",
            client_ip=get_client_ip(request),
        )

        return success_response(
            message=result["message"],
            meta=_meta("authenticated"),
            data=result["data"],
        )

    except DeviceAuthServiceError as exc:
        return _service_error_response(exc)
    except Exception as exc:
        return _unhandled_error(
            "Session restore failed",
            "AUTH_SESSION_RESTORE_FAILED",
            exc,
        )


@router.post("/device/logout")
def logout(payload: DeviceLogoutRequest):
    try:
        result = logout_device_session(
            refresh_token=payload.refresh_token,
            device_id=payload.device_id,
        )

        return success_response(
            message=result["message"],
            meta=_meta("logged_out"),
            data=result["data"],
        )

    except DeviceAuthServiceError as exc:
        return _service_error_response(exc)
    except Exception as exc:
        return _unhandled_error(
            "Logout failed",
            "AUTH_LOGOUT_FAILED",
            exc,
        )


@router.post("/device/forgot-password")
def forgot_password(payload: DeviceForgotPasswordRequest):
    try:
        result = forgot_device_password(payload.username)

        return success_response(
            message=result["message"],
            meta=_meta("password_reset_requested"),
            data=result["data"],
        )

    except DeviceAuthServiceError as exc:
        return _service_error_response(exc)
    except Exception as exc:
        return _unhandled_error(
            "Forgot password request failed",
            "AUTH_PASSWORD_RESET_FAILED",
            exc,
        )
