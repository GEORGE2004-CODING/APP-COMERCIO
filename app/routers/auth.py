from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from app.database.database import get_db, transaction
from app.schemas.user import UserUpdate, UserResponse, UserListResponse, UserLogin, UserToken, UserChangePassword, UserResetPassword
from app.models.user import User
from app.core.security import hash_password, verify_password, create_access_token, get_current_user, create_refresh_token, decode_access_token
from app.core.config import settings
from app.schemas.user import UserRole

router = APIRouter(prefix="/auth", tags=["auth"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login",
                                    

@router.post("/login", response_model=UserToken)
async def login_path(user_login: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == user_login.username).first()
    if not user or not verify_password(user_login.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid username or password")
    access_token = create_access_token()
