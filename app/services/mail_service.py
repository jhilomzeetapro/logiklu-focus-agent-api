import json
import os
import ssl
from datetime import datetime
from typing import Any, Dict, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from app.db.master import get_master_connection


MAIL_AUTH_URL = os.getenv(
    "LOGIKLU_MAIL_AUTH_URL",
    "https://emailsendapi.zeetapro.com/mails.php?action=authorization",
)

MAIL_SEND_URL = os.getenv(
    "LOGIKLU_MAIL_SEND_URL",
    "https://emailsendapi.zeetapro.com/mails.php?action=sendemail",
)

DEFAULT_FROM_NAME = "LogiKlu Support"
DEFAULT_FROM_EMAIL = "info@logiklu.com"


class MailServiceError(Exception):
    def __init__(
        self,
        message: str,
        error_code: str,
        http_status: int = 500,
        data: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.http_status = http_status
        self.data = data or {}


def _json_string(value: Any, default: Any) -> str:
    if value is None or value == "":
        return json.dumps(default, separators=(",", ":"))

    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except Exception as exc:
            raise MailServiceError(
                "Invalid JSON mail parameter",
                "MAIL_PARAMETER_INVALID",
                422,
            ) from exc

        return json.dumps(parsed, separators=(",", ":"), default=str)

    return json.dumps(value, separators=(",", ":"), default=str)


def _post_form(
    url: str,
    payload: Dict[str, Any],
    timeout: int = 10,
) -> Tuple[int, str]:
    encoded = urlencode(
        {
            key: (
                json.dumps(value, separators=(",", ":"), default=str)
                if isinstance(value, (dict, list))
                else str(value)
            )
            for key, value in payload.items()
        }
    ).encode("utf-8")

    request = Request(
        url,
        data=encoded,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "LogiKlu-API-MailService/1.0",
        },
    )

    context = ssl.create_default_context()

    try:
        with urlopen(request, timeout=timeout, context=context) as response:
            return (
                int(response.getcode()),
                response.read().decode("utf-8", errors="replace"),
            )

    except HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""

        raise MailServiceError(
            f"Mail provider returned HTTP {exc.code}",
            "MAIL_PROVIDER_HTTP_ERROR",
            502,
            {
                "provider_http_status": exc.code,
                "provider_response": body[:1000],
            },
        ) from exc

    except URLError as exc:
        raise MailServiceError(
            "Unable to connect to mail provider",
            "MAIL_PROVIDER_CONNECTION_FAILED",
            502,
            {"reason": str(exc.reason)},
        ) from exc

    except TimeoutError as exc:
        raise MailServiceError(
            "Mail provider request timed out",
            "MAIL_PROVIDER_TIMEOUT",
            504,
        ) from exc

    except Exception as exc:
        raise MailServiceError(
            "Mail provider request failed",
            "MAIL_PROVIDER_REQUEST_FAILED",
            502,
            {"error": str(exc)},
        ) from exc


def _parse_json_response(raw: str, stage: str) -> Dict[str, Any]:
    raw = str(raw or "").strip()

    if not raw:
        raise MailServiceError(
            f"Mail provider returned an empty response during {stage}",
            "MAIL_PROVIDER_EMPTY_RESPONSE",
            502,
            {"stage": stage},
        )

    try:
        parsed = json.loads(raw)
    except Exception as exc:
        raise MailServiceError(
            f"Mail provider returned invalid JSON during {stage}",
            "MAIL_PROVIDER_INVALID_RESPONSE",
            502,
            {
                "stage": stage,
                "provider_response": raw[:1000],
            },
        ) from exc

    if not isinstance(parsed, dict):
        raise MailServiceError(
            f"Mail provider returned an invalid response during {stage}",
            "MAIL_PROVIDER_INVALID_RESPONSE",
            502,
            {
                "stage": stage,
                "provider_response": parsed,
            },
        )

    return parsed


def _authorize_mail_provider(timeout: int = 10) -> Tuple[str, Dict[str, Any]]:
    section = os.getenv("LOGIKLU_MAIL_SECTION", "LogiKlu").strip() or "LogiKlu"
    auth_password = os.getenv("LOGIKLU_MAIL_AUTH_PASSWORD", "").strip()

    if not auth_password:
        raise MailServiceError(
            "Mail authorization password is not configured",
            "MAIL_AUTH_CONFIG_MISSING",
            500,
        )

    http_status, raw = _post_form(
        MAIL_AUTH_URL,
        {
            "section": section,
            "authentication_password": auth_password,
        },
        timeout=timeout,
    )

    if http_status < 200 or http_status >= 300:
        raise MailServiceError(
            "Unable to authorize with mail service",
            "MAIL_AUTH_FAILED",
            502,
            {"provider_http_status": http_status},
        )

    response = _parse_json_response(raw, "authorization")

    if str(response.get("status") or "").lower() != "success":
        raise MailServiceError(
            "Unable to authorize with mail service",
            "MAIL_AUTH_FAILED",
            502,
            {"provider_response": response},
        )

    token = ""
    if isinstance(response.get("data"), dict):
        token = str(response["data"].get("token") or "").strip()

    if not token:
        raise MailServiceError(
            "Mail service authorization token was not returned",
            "MAIL_AUTH_TOKEN_MISSING",
            502,
            {"provider_response": response},
        )

    return token, response


def _insert_mail_queue(
    *,
    token_section: str,
    client_info: str,
    email_recepients_to: str,
    email_recepients_cc: str,
    email_recepients_bcc: str,
    email_subject: str,
    email_body: str,
    attachments: str,
    email_form: str,
    in_reply_to: str,
) -> int:
    connection = None

    try:
        connection = get_master_connection()

        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO email_send_db.email_send
                (
                    token_section,
                    client_info,
                    email_recepients_to,
                    email_recepients_cc,
                    email_recepients_bcc,
                    email_subject,
                    email_body,
                    attachments,
                    email_form,
                    in_reply_to,
                    created_date
                )
                VALUES
                (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    token_section,
                    client_info,
                    email_recepients_to,
                    email_recepients_cc,
                    email_recepients_bcc,
                    email_subject,
                    email_body,
                    attachments,
                    email_form,
                    in_reply_to,
                    datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                ),
            )

            mail_id = int(cursor.lastrowid or 0)

        connection.commit()

        if mail_id <= 0:
            raise MailServiceError(
                "Unable to create email queue record",
                "MAIL_QUEUE_FAILED",
                500,
            )

        return mail_id

    except MailServiceError:
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

        raise MailServiceError(
            "Unable to queue email",
            "MAIL_QUEUE_FAILED",
            500,
            {"error": str(exc)},
        ) from exc

    finally:
        if connection:
            connection.close()


def _send_queued_mail(
    token: str,
    mail_id: int,
    timeout: int = 10,
) -> Dict[str, Any]:
    http_status, raw = _post_form(
        MAIL_SEND_URL,
        {
            "token": token,
            "mail_id": mail_id,
        },
        timeout=timeout,
    )

    if http_status < 200 or http_status >= 300:
        raise MailServiceError(
            "Email could not be sent",
            "MAIL_SEND_FAILED",
            502,
            {
                "mail_id": mail_id,
                "provider_http_status": http_status,
            },
        )

    response = _parse_json_response(raw, "sendemail")

    if str(response.get("status") or "").lower() != "success":
        raise MailServiceError(
            "Email could not be sent",
            "MAIL_SEND_FAILED",
            502,
            {
                "mail_id": mail_id,
                "provider_response": response,
            },
        )

    return response


def send_email(
    params: Dict[str, Any],
    timeout: int = 10,
) -> Dict[str, Any]:
    """
    Python equivalent of the existing PHP emailsendprocess.php flow:

      1. Authorize with emailsendapi.zeetapro.com
      2. Insert email into email_send_db.email_send
      3. Trigger provider sendemail using token + mail_id

    The caller never supplies the provider authentication password.
    It is read from LOGIKLU_MAIL_AUTH_PASSWORD.
    """
    if not params:
        raise MailServiceError(
            "Some parameters are missing",
            "MAIL_PARAMETERS_MISSING",
            422,
        )

    subject = str(params.get("email_subject") or "").strip()
    body = str(params.get("email_body") or "")

    if not subject:
        raise MailServiceError(
            "Email subject is required",
            "MAIL_SUBJECT_REQUIRED",
            422,
        )

    if not body:
        raise MailServiceError(
            "Email body is required",
            "MAIL_BODY_REQUIRED",
            422,
        )

    recipients_to = _json_string(
        params.get("email_recepients_to"),
        [],
    )

    try:
        to_list = json.loads(recipients_to)
    except Exception:
        to_list = []

    if not isinstance(to_list, list) or len(to_list) == 0:
        raise MailServiceError(
            "At least one email recipient is required",
            "MAIL_RECIPIENT_REQUIRED",
            422,
        )

    client_info = _json_string(params.get("client_info"), [])
    recipients_cc = _json_string(params.get("email_recepients_cc"), [])
    recipients_bcc = _json_string(params.get("email_recepients_bcc"), [])
    attachments = _json_string(params.get("attachments"), [])

    email_form = _json_string(
        params.get("email_form"),
        {
            "name": DEFAULT_FROM_NAME,
            "email": DEFAULT_FROM_EMAIL,
        },
    )

    in_reply_to = _json_string(
        params.get("in_reply_to"),
        {
            "name": DEFAULT_FROM_NAME,
            "email": DEFAULT_FROM_EMAIL,
        },
    )

    token, auth_response = _authorize_mail_provider(timeout=timeout)

    section = os.getenv("LOGIKLU_MAIL_SECTION", "LogiKlu").strip() or "LogiKlu"

    mail_id = _insert_mail_queue(
        token_section=section,
        client_info=client_info,
        email_recepients_to=recipients_to,
        email_recepients_cc=recipients_cc,
        email_recepients_bcc=recipients_bcc,
        email_subject=subject,
        email_body=body,
        attachments=attachments,
        email_form=email_form,
        in_reply_to=in_reply_to,
    )

    send_response = _send_queued_mail(
        token=token,
        mail_id=mail_id,
        timeout=timeout,
    )

    return {
        "status": "success",
        "message": "Email sent successfully",
        "data": {
            "mail_id": mail_id,
            "mail_status": str(send_response.get("status") or "success"),
            "provider_response": send_response,
        },
    }
