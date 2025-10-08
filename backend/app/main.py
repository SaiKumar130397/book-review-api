import os
import uuid
import jwt

from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException, status, Response, Request, Cookie
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from sqlalchemy import  create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import Session, sessionmaker, relationship, declarative_base
from argon2 import PasswordHasher, exceptions as argon2_exceptions 
from dotenv import load_dotenv 

load_dotenv()

app = FastAPI()

@app.get("/api/healthcheck")
async def healthcheck():
    return {"status": "200", "message": "OK"}

@app.post("/signup", response_model=MeOut, status_code=status.HTTP_201_CREATED)
def signup(payload: SignupIn, db: Session = Depends(get_db)):
    if len(payload.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if db.query(User).filter(User.email == payload.email.lower()).first():
        raise HTTPException(status_code=400, detail="A user with that email already exists")

    hashed = hash_password(payload.password)
    user = User(email=payload.email.lower(), name=payload.name, password_hash=hashed)
    db.add(user)
    db.commit()
    db.refresh(user)

    return user

@app.post("/login", response_model=TokenOut)
def login(payload: LoginIn, response: Response, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email.lower()).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token, access_exp = create_access_token(str(user.id))

    jti = str(uuid.uuid4())
    refresh_token, refresh_exp = create_refresh_token(str(user.id), jti) 

    rt = RefreshToken(jti=jti, expires_at=refresh_exp, user_id=user.id)
    db.add(rt)
    db.commit()

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="lax",
        expires=int(refresh_exp.timestamp())
    )
    return TokenOut(access_token=access_token, expires_at=access_exp)
    

    