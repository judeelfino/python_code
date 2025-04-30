from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session

from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from database import SessionLocal, engine
from models import Base
from service import AuthService
from database import get_db
from schemas import UserCreate, UserLogin

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

Base.metadata.create_all(bind=engine)

@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    auth_service = AuthService(db)
    return auth_service.register_user(user.email, user.name, user.password)

@app.post("/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    auth_service = AuthService(db)
    return auth_service.authenticate_user(user.email, user.password)
