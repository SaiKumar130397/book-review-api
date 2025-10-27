import os
import uuid
import jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, status, Response, Cookie, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session
from argon2 import PasswordHasher, exceptions as argon2_exceptions

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY", "supersecret123")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
FRONTEND_ORIGINS = os.getenv("FRONTEND_ORIGINS", "http://localhost:3000")

print(f"DATABASE_URL: {DATABAE_URL}")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, nullable=True)
    password_hash = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True, index=True)
    jti = Column(String, unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    revoked = Column(Boolean, default=False)
    user = relationship("User", back_populates="refresh_tokens")


class SignupIn(BaseModel):
    email: EmailStr
    password: str
    name: str | None = None

class LoginIn(BaseModel):
    email: EmailStr
    password: str

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime

class MeOut(BaseModel):
    id: int
    email: EmailStr
    name: str | None
    created_at: datetime
    class Config:
        orm_mode = True


ph = PasswordHasher()

def hash_password(password: str) -> str:
    return ph.hash(password)

def verify_password(stored_hash: str, plain_password: str) -> bool:
    try:
        return ph.verify(stored_hash, plain_password)
    except argon2_exceptions.VerifyMismatchError:
        return False

def create_access_token(subject: str):
    now = datetime.utcnow()
    expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": str(subject), "exp": expire, "iat": now, "type": "access"}
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token, expire

def create_refresh_token(subject: str, jti: str):
    now = datetime.utcnow()
    expire = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    payload = {"sub": str(subject), "jti": jti, "exp": expire, "iat": now, "type": "refresh"}
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token, expire

def decode_token(token: str):
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

security = HTTPBearer(auto_error=False)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    token = credentials.credentials
    try:
        data = decode_token(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Access token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

    if data.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")

    user = db.query(User).filter(User.id == int(data["sub"])).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


app = FastAPI(title="BookReview Auth API (Supabase)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGINS],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)

@app.post("/auth/signup", response_model=MeOut)
def signup(payload: SignupIn, db: Session = Depends(get_db)):
    if len(payload.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if db.query(User).filter(User.email == payload.email.lower()).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        email=payload.email.lower(),
        name=payload.name,
        password_hash=hash_password(payload.password)
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

@app.post("/auth/login", response_model=TokenOut)
def login(payload: LoginIn, response: Response, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email.lower()).first()
    if not user or not verify_password(user.password_hash, payload.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token, access_exp = create_access_token(str(user.id))
    jti = str(uuid.uuid4())
    refresh_token, refresh_exp = create_refresh_token(str(user.id), jti)

    rt = RefreshToken(jti=jti, user_id=user.id, expires_at=refresh_exp)
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

@app.post("/auth/refresh", response_model=TokenOut)
def refresh(response: Response, refresh_token: str = Cookie(None), db: Session = Depends(get_db)):
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Missing refresh token")
    try:
        data = decode_token(refresh_token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    if data.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type")

    rt = db.query(RefreshToken).filter(
        RefreshToken.jti == data["jti"],
        RefreshToken.revoked == False
    ).first()
    if not rt or rt.expires_at < datetime.utcnow():
        raise HTTPException(status_code=401, detail="Refresh token invalid or expired")

    
    rt.revoked = True
    db.commit()

    
    new_jti = str(uuid.uuid4())
    new_refresh_token, new_refresh_exp = create_refresh_token(data["sub"], new_jti)
    db.add(RefreshToken(jti=new_jti, user_id=int(data["sub"]), expires_at=new_refresh_exp))
    db.commit()

    response.set_cookie(
        key="refresh_token",
        value=new_refresh_token,
        httponly=True,
        secure=True,
        samesite="lax",
        expires=int(new_refresh_exp.timestamp())
    )

    new_access_token, new_access_exp = create_access_token(data["sub"])
    return TokenOut(access_token=new_access_token, expires_at=new_access_exp)

@app.post("/auth/logout", status_code=204)
def logout(response: Response, refresh_token: str = Cookie(None), db: Session = Depends(get_db)):
    if refresh_token:
        try:
            data = decode_token(refresh_token)
            rt = db.query(RefreshToken).filter(RefreshToken.jti == data.get("jti")).first()
            if rt:
                rt.revoked = True
                db.commit()
        except Exception:
            pass
    response.delete_cookie("refresh_token")
    return Response(status_code=204)

@app.get("/auth/me", response_model=MeOut)
def me(current_user: User = Depends(get_current_user)):
    return current_user
