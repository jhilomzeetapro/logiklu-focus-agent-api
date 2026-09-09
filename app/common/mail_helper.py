import json
import os
import ssl
from datetime import datetime
from html import escape
from typing import Any, Dict, Tuple
from urllib.parse import urlencode
from urllib.request import Request, urlopen


MAIL_PROCESS_URL = os.getenv(
    "LOGIKLU_EMAIL_PROCESS_URL",
    "https://logiklu.com/app/emailsendprocess.php",
)

LOGIKLU_ROOT_URL = os.getenv(
    "LOGIKLU_ROOT_URL",
    "https://logiklu.com/",
).rstrip("/") + "/"

DEFAULT_FROM_NAME = "LogiKlu Support"
DEFAULT_FROM_EMAIL = "info@logiklu.com"


class MailHelperError(Exception):
    pass


def _json_string(value: Any, default: Any) -> str:
    if value is None or value == "":
        return json.dumps(default, separators=(",", ":"))

    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return json.dumps(parsed, separators=(",", ":"))
        except Exception as exc:
            raise MailHelperError("Invalid JSON value supplied to mail helper") from exc

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
            "User-Agent": "LogiKlu-API-MailHelper/1.0",
        },
    )

    context = ssl.create_default_context()

    try:
        with urlopen(request, timeout=timeout, context=context) as response:
            status_code = int(response.getcode())
            body = response.read().decode("utf-8", errors="replace")
            return status_code, body
    except Exception as exc:
        raise MailHelperError(f"LogiKlu email process request failed: {exc}") from exc


def prepare_mail_template(name: str = "", mail_content: str = "") -> str:
    now = datetime.now()
    today = f"{now.strftime('%B')} {now.day}, {now.year}"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{ margin: 0; padding: 0; font-size: 14px; }}
        p {{ font-family: Arial, Helvetica, sans-serif; font-size: 14px; margin: 0; padding: 0 10px; }}
        td {{ font-family: Arial, Helvetica, sans-serif; }}
        ul {{ padding: 0 0 0 25px; margin: 0; }}
        li {{ margin-left: 0; }}
        .hishab-table tr td table tr td {{ border-bottom: 0 !important; background-color: transparent !important; }}
        .total-price-tr td {{ font-family: Arial, Helvetica, sans-serif; background-color: transparent !important; border-top: 1px solid #000; font-weight: 600; }}
        .heading-of-td {{ letter-spacing: 1px; }}
        .total-price-tr td:nth-child(2n) {{ font-size: 19px; }}
        .logo-td a img {{ float: left; }}
        .logo-td a small {{ text-decoration: none; float: left; clear: both; font-family: Arial, Helvetica, sans-serif; color: #155e9b; font-weight: bold; position: relative; font-size: 13px; }}
        .mainTh-heading {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; color: #333; }}
    </style>
</head>
<body>
    <table align="center" bgcolor="#fff" cellpadding="0" cellspacing="0"
           style="border: 10px solid #155e9b; width: 700px; max-width: 100%; padding: 10px"
           id="billingInvoice">
        <tbody style="background-color: #fff;">
            <tr>
                <td valign="top" align="left" style="padding: 0 10px">
                    <table cellpadding="0" cellspacing="0" style="width: 100%">
                        <tr><td style="width: 100%; padding: 7px 0;"></td></tr>
                        <tr>
                            <td class="logo-td" align="left" valign="top" style="padding: 0; width: 50%; float: left;">
                                <a href="#">
                                    <img src="{LOGIKLU_ROOT_URL}templates/creative/includes/images/newimages/logo.jpg" alt="logiklu" width="120">
                                    <small>Sales Intelligence Automation</small>
                                </a>
                            </td>
                            <td class="date-td" align="left" valign="top" style="width: 50%; float: left;">
                                <p style="padding: 0; text-align: right; color: #4a4848;">{today}</p>
                            </td>
                        </tr>
                    </table>
                </td>
            </tr>
            <tr><td style="width: 100%; padding: 7px 0; border-bottom: 1px solid #ddd;"></td></tr>
            <tr><td style="width: 100%; padding: 8px 0;"></td></tr>
            <tr>
                <td style="border-bottom: 1px solid #ddd; padding-bottom: 15px">[[MAINHTML]]</td>
            </tr>
            <tr>
                <td valign="top" align="center" style="padding: 15px 0; color: #444">
                    <p style="font-size: 12px;">&copy; {today} LogiKlu Inc. All rights reserved</p>
                </td>
            </tr>
        </tbody>
    </table>
    <a style="color:#FFF;font-size:0px;"
       href="{{unsubscribe:https://logiklu.com}}"
       target="_blank"
       title="Click to unsubscribe">a</a>
</body>
</html>"""

    html = html.replace("[[MAINHTML]]", mail_content or "")
    first_name = str(name or "").strip().split(" ")[0] if str(name or "").strip() else ""
    html = html.replace("[[NAME]]", first_name)
    return html


def send_email_postman(
    params: Dict[str, Any],
    timeout: int = 10,
) -> Dict[str, Any]:
    if not params:
        raise MailHelperError("Some parameters are missing")

    section = os.getenv("LOGIKLU_MAIL_SECTION", "LogiKlu").strip()
    auth_password = os.getenv("LOGIKLU_MAIL_AUTH_PASSWORD", "").strip()

    if not auth_password:
        raise MailHelperError("LOGIKLU_MAIL_AUTH_PASSWORD is not configured")

    recipients_to = _json_string(params.get("email_recepients_to"), [])
    if recipients_to == "[]":
        raise MailHelperError("email_recepients_to is required")

    subject = str(params.get("email_subject") or "").strip()
    body = str(params.get("email_body") or "")

    if not subject:
        raise MailHelperError("email_subject is required")
    if not body:
        raise MailHelperError("email_body is required")

    payload = {
        "client_info": _json_string(params.get("client_info"), []),
        "email_recepients_to": recipients_to,
        "email_recepients_cc": _json_string(params.get("email_recepients_cc"), []),
        "email_recepients_bcc": _json_string(params.get("email_recepients_bcc"), []),
        "email_subject": subject,
        "email_body": body,
        "attachments": _json_string(params.get("attachments"), []),
        "email_form": _json_string(
            params.get("email_form"),
            {"name": DEFAULT_FROM_NAME, "email": DEFAULT_FROM_EMAIL},
        ),
        "in_reply_to": _json_string(
            params.get("in_reply_to"),
            {"name": DEFAULT_FROM_NAME, "email": DEFAULT_FROM_EMAIL},
        ),
        "post_paramenter": json.dumps(
            {
                "section": section,
                "authentication_password": auth_password,
            },
            separators=(",", ":"),
        ),
    }

    status_code, response_body = _post_form(
        MAIL_PROCESS_URL,
        payload,
        timeout=timeout,
    )

    if status_code < 200 or status_code >= 300:
        raise MailHelperError(
            f"LogiKlu email process returned HTTP {status_code}"
        )

    response_body = (response_body or "").strip()

    if response_body == "":
        return {
            "status": "success",
            "http_status": status_code,
            "response": None,
        }

    try:
        parsed = json.loads(response_body)
    except Exception:
        return {
            "status": "success",
            "http_status": status_code,
            "raw_response": response_body,
        }

    if isinstance(parsed, dict) and str(parsed.get("status", "")).lower() == "error":
        return {
            "status": "error",
            "http_status": status_code,
            "response": parsed,
        }

    return {
        "status": "success",
        "http_status": status_code,
        "response": parsed,
    }


def send_logiklu_otp_email(
    recipient_name: str,
    recipient_email: str,
    otp: str,
    timeout: int = 10,
) -> Dict[str, Any]:
    recipient_name = str(recipient_name or "").strip()
    recipient_email = str(recipient_email or "").strip()
    otp = str(otp or "").strip()

    if not recipient_email:
        raise MailHelperError("Recipient email is required")
    if not otp:
        raise MailHelperError("OTP is required")

    content = f"""
        <p style="font-size:1.1em">Hi [[NAME]],</p>
        <p>Here is your OTP for login.</p>
        <h2 style="background: #155e9b;margin: 0 auto;width: max-content;padding: 0 10px;color: #fff;border-radius: 4px;">
            {escape(otp)}
        </h2>
        <p style="font-size:0.9em;">Regards,<br />LogiKlu Support</p>
    """

    return send_email_postman(
        {
            "client_info": {
                "client_name": "LogiKlu",
                "website": "https://logiklu.com",
                "section": "OTP",
            },
            "email_recepients_to": [
                {"name": recipient_name, "email": recipient_email}
            ],
            "email_subject": "OTP for login into LogiKlu",
            "email_body": prepare_mail_template(recipient_name, content),
            "email_form": {
                "name": DEFAULT_FROM_NAME,
                "email": DEFAULT_FROM_EMAIL,
            },
            "in_reply_to": {
                "name": DEFAULT_FROM_NAME,
                "email": DEFAULT_FROM_EMAIL,
            },
        },
        timeout=timeout,
    )


def send_logiklu_password_reset_email(
    recipient_name: str,
    recipient_email: str,
    reset_link: str,
    timeout: int = 10,
) -> Dict[str, Any]:
    recipient_name = str(recipient_name or "").strip()
    recipient_email = str(recipient_email or "").strip()
    reset_link = str(reset_link or "").strip()

    if not recipient_email:
        raise MailHelperError("Recipient email is required")
    if not reset_link:
        raise MailHelperError("Password reset link is required")

    safe_link = escape(reset_link, quote=True)

    content = f"""
        <p style="font-size:1.1em">Hi [[NAME]],</p>
        <p>
            Please <a href="{safe_link}" target="_blank">click here</a>
            to reset your password. This link will expire in 48 hours.
        </p>
        <p>&nbsp;</p>
        <p style="font-size:0.9em;">Regards,<br />LogiKlu Support</p>
    """

    return send_email_postman(
        {
            "client_info": {
                "client_name": "LogiKlu",
                "website": "https://logiklu.com",
                "section": "Password Reset",
            },
            "email_recepients_to": [
                {"name": recipient_name, "email": recipient_email}
            ],
            "email_subject": "Reset Password for LogiKlu",
            "email_body": prepare_mail_template(recipient_name, content),
            "email_form": {
                "name": DEFAULT_FROM_NAME,
                "email": DEFAULT_FROM_EMAIL,
            },
            "in_reply_to": {
                "name": DEFAULT_FROM_NAME,
                "email": DEFAULT_FROM_EMAIL,
            },
        },
        timeout=timeout,
    )
