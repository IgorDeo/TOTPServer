from pydantic import BaseModel, EmailStr


class UserCreate(BaseModel):
    email: EmailStr
    name: str


class UserResponse(BaseModel):
    id: str
    email: str
    name: str

    class Config:
        from_attributes = True


class TOTPValidate(BaseModel):
    user_id: str
    totp_code: str
