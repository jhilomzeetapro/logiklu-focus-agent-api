import hmac
import os

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse

from app.core.response import (
    current_utc_datetime,
    error_response,
    success_response,
)
from app.core.security import get_api_environment
from app.schemas.mail import MailSendRequest
from app.services.mail_service import (
    MailServiceError,
    send_email,
)


router = APIRouter()


def _model_to_dict(model):
    if model is None:
        return None

    if hasattr(model, "model_dump"):
        return model.model_dump()

    return model.dict()


def _meta():
    return {
        "generated_at": current_utc_datetime(),
        "mode": "mail",
        "environment": get_api_environment(),
        "schema_version": "logiklu_mail.v1",
    }


def _service_error_response(exc: MailServiceError) -> JSONResponse:
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


def _validate_mail_password(mail_password: str) -> None:
    """
    Protect /mail/emailsend with one service-level password.

    This is NOT related to lk_agent_api_clients and does not use X-API-KEY.
    """
    configured_password = os.getenv(
        "LOGIKLU_MAIL_ENDPOINT_PASSWORD",
        "",
    ).strip()

    if not configured_password:
        raise MailServiceError(
            "Mail endpoint password is not configured",
            "MAIL_ENDPOINT_AUTH_CONFIG_MISSING",
            500,
        )

    supplied_password = str(mail_password or "").strip()

    if not supplied_password:
        raise MailServiceError(
            "Mail endpoint password is required",
            "MAIL_ENDPOINT_PASSWORD_MISSING",
            401,
        )

    if not hmac.compare_digest(
        supplied_password,
        configured_password,
    ):
        raise MailServiceError(
            "Invalid mail endpoint password",
            "MAIL_ENDPOINT_PASSWORD_INVALID",
            401,
        )


@router.post("/mail/emailsend")
def email_send(
    payload: MailSendRequest,
    request: Request,
    x_mail_password: str = Header(
        default="",
        alias="X-MAIL-PASSWORD",
    ),
):
    try:
        _validate_mail_password(x_mail_password)

        params = _model_to_dict(payload)

        params["email_recepients_to"] = [
            _model_to_dict(item)
            for item in payload.email_recepients_to
        ]

        params["email_recepients_cc"] = [
            _model_to_dict(item)
            for item in (payload.email_recepients_cc or [])
        ]

        params["email_recepients_bcc"] = [
            _model_to_dict(item)
            for item in (payload.email_recepients_bcc or [])
        ]

        params["email_form"] = _model_to_dict(payload.email_form)
        params["in_reply_to"] = _model_to_dict(payload.in_reply_to)

        result = send_email(params)

        return success_response(
            message=result["message"],
            meta=_meta(),
            data=result["data"],
        )

    except MailServiceError as exc:
        return _service_error_response(exc)

    except Exception as exc:
        return JSONResponse(
            status_code=500,
            content=error_response(
                message="Unable to send email",
                error_code="MAIL_SEND_PROCESS_FAILED",
                data={
                    "error": str(exc),
                    "timestamp": current_utc_datetime(),
                },
            ),
        )
