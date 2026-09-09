from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class MailRecipient(BaseModel):
    name: Optional[str] = Field(default="", max_length=255)
    email: str = Field(..., min_length=3, max_length=320)


class MailIdentity(BaseModel):
    name: Optional[str] = Field(default="LogiKlu Support", max_length=255)
    email: str = Field(default="info@logiklu.com", min_length=3, max_length=320)


class MailSendRequest(BaseModel):
    client_info: Optional[Dict[str, Any]] = None

    # Keep existing LogiKlu field spelling for compatibility.
    email_recepients_to: List[MailRecipient] = Field(..., min_length=1)
    email_recepients_cc: Optional[List[MailRecipient]] = None
    email_recepients_bcc: Optional[List[MailRecipient]] = None

    email_subject: str = Field(..., min_length=1, max_length=1000)
    email_body: str = Field(..., min_length=1)

    attachments: Optional[List[Any]] = None

    email_form: Optional[MailIdentity] = None
    in_reply_to: Optional[MailIdentity] = None
