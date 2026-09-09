from typing import Optional

from pydantic import BaseModel, Field


class DeviceLoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=255)
    password: str = Field(..., min_length=1, max_length=255)
    client_type: str = Field(default="mobile", min_length=1, max_length=20)
    device_id: str = Field(..., min_length=8, max_length=128)
    device_name: Optional[str] = Field(default=None, max_length=255)
    device_os: Optional[str] = Field(default=None, max_length=50)
    os_version: Optional[str] = Field(default=None, max_length=50)
    app_version: Optional[str] = Field(default=None, max_length=50)
    current_timezone: Optional[str] = Field(default="UTC", max_length=100)


class DeviceOtpVerifyRequest(BaseModel):
    challenge_id: str = Field(..., min_length=16, max_length=128)
    otp: str = Field(..., min_length=6, max_length=6)
    device_id: str = Field(..., min_length=8, max_length=128)


class DeviceOtpResendRequest(BaseModel):
    challenge_id: str = Field(..., min_length=16, max_length=128)
    device_id: str = Field(..., min_length=8, max_length=128)


class DeviceSessionRestoreRequest(BaseModel):
    refresh_token: str = Field(..., min_length=32, max_length=512)
    device_id: str = Field(..., min_length=8, max_length=128)
    app_version: Optional[str] = Field(default=None, max_length=50)
    current_timezone: Optional[str] = Field(default="UTC", max_length=100)


class DeviceLogoutRequest(BaseModel):
    refresh_token: str = Field(..., min_length=32, max_length=512)
    device_id: str = Field(..., min_length=8, max_length=128)


class DeviceForgotPasswordRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=255)
