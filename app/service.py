from sqlalchemy.orm import Session
from models import User
from passlib.context import CryptContext
from fastapi import HTTPException, status
from utils import create_access_token
from datetime import timedelta

from database import get_db

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class AuthService:
    def __init__(self, db: Session):
        self.db = db

    def get_user_by_email(self, email: str):
        return self.db.query(User).filter(User.email == email).first()

    def register_user(self, email: str, name: str, password: str):
        user = self.get_user_by_email(email)
        if user:
            raise HTTPException(status_code=400, detail="Email already registered")
        
        hashed_password = pwd_context.hash(password)
        new_user = User(email=email, name=name, hashed_password=hashed_password)
        self.db.add(new_user)
        self.db.commit()
        self.db.refresh(new_user)
        return {"msg": "User registered successfully"}

    def authenticate_user(self, email: str, password: str):
        user = self.get_user_by_email(email)
        if not user or not pwd_context.verify(password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        access_token_expires = timedelta(minutes=30)
        access_token = create_access_token(
            data={"sub": user.email}, expires_delta=access_token_expires
        )
        return {"access_token": access_token, "token_type": "bearer"}
