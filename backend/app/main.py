import os
import uuid
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status, Response, Request, Cookie
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy import column, integer, string, boolean, datetime, create_engine, foreign_key
from sqlalchemy.orm import Session, sessionmaker, relationship 
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.declarative import declarative_base 

import jwt
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

    hashed = hash_password(payload.password)
    user = User(email=payload.email.lower(), name=payload.name, password_hash=hashed)
    db.add(user)
    try:
        db.commit()
        db.refresh(user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="A user with that email already exists")

    return MeOut(id=user.id, email=user.email, name=user.name, created_at=user.created_at)

@app.post("/login", response_model=TokenOut)
def login(payload: LoginIn, response: Response, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email.lower()).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    
    access_token, access_exp = create_access_token(subject=str(user.id))

    jti = str(uuid.uuid4())
    refresh_token, refresh_exp = create_refresh_token(subject=str(user.id), jti=jti)

    rt = RefreshToken(jti=jti, expires_at=refresh_exp, user_id=user.id)
    db.add(rt)
    db.commit()

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=REFRESH_COOKIE_HTTPONLY,
        secure=REFRESH_COOKIE_SECURE,
        samesite=REFRESH_COOKIE_SAMESITE,
        expires=int(refresh_exp.timestamp())
    
    return TokenOut(access_token=access_token, expires_at=access_exp)
    

    