from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from datetime import datetime
from enum import Enum

class UserRole(str, Enum):
    ADMIN = "admin"
    USER = "user"  

class UserBase(BaseModel):
    first_names: str = Field(..., min_length=1, max_length=50)
    last_names: str = Field(..., min_length=1, max_length=50)
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    ID_CARD: str = Field(..., min_length=8, max_length=20)
    is_active: bool = True

class UserCreate(UserBase):
    password: str = Field(..., min_length=8, max_length=128)

    class model_config:
        orm_mode = True
        anystr_strip_whitespace = True


class UserInDB(UserBase):
    id: int
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    ID_CARD: str
    is_active: bool = True
    full_name: Optional[str] = None
    hashed_password: str
    role: UserRole = UserRole.USER
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = None

    class model_config:
        orm_mode = True
        anystr_strip_whitespace = True


class UserUpdate(UserBase):
    first_names: Optional[str] = Field(None, min_length=1, max_length=50)
    last_names: Optional[str] = Field(None, min_length=1, max_length=50)
    password: Optional[str] = Field(None, min_length=8, max_length=128)
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    email: Optional[EmailStr] = None
    is_active: Optional[bool] = None


class UserResponse(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    role: UserRole
    full_name: Optional[str] = None
    
    
    class model_config:
        orm_mode = True
        anystr_strip_whitespace = True

class UserListResponse(BaseModel):
    users: List[UserResponse]
    total: int

    class model_config:
        orm_mode = True
        anystr_strip_whitespace = True

class UserLogin(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=128)

class UserToken(BaseModel):
    access_token: str
    token_type: str = "bearer"

#PBJETOS RAROS

class UserTokenData(BaseModel):
    id: int
    username: str
    role: UserRole

class UserChangePassword(BaseModel):
    current_password: str = Field(..., min_length=8, max_length=128)
    new_password: str = Field(..., min_length=8, max_length=128)

class UserResetPassword(BaseModel):
    email: EmailStr
    new_password: str = Field(..., min_length=8, max_length=128)
