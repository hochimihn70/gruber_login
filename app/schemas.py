"""Request-Bodies der API.

Defaults sind leer, damit fehlende Felder eine normale Fehlermeldung ergeben
(400) statt der technischen 422-Antwort von Pydantic.
"""

from pydantic import BaseModel


class RegisterRequest(BaseModel):
    email: str = ""
    password: str = ""
    auth_method: str = "password"


class LoginRequest(BaseModel):
    email: str = ""
    password: str = ""


class Verify2FARequest(BaseModel):
    email: str = ""
    code: str = ""


class ForgotPasswordRequest(BaseModel):
    email: str = ""


class ResetPasswordRequest(BaseModel):
    email: str = ""
    code: str = ""
    new_password: str = ""
