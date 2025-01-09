from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from pydantic import BaseModel  # 데이터 검증을 위한 Pydantic 모델
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

from passlib.context import CryptContext
from pydantic_settings import BaseSettings, SettingsConfigDict
from fastapi.security import (
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm,
)  # OAuth2 인증 관련 클래스
from datetime import datetime, timezone, timedelta  # 시간 관련 처리를 위한 클래스
from jose import jwt  # JWT 토큰 생성 및 검증을 위한 라이브러리

# Database 설정
SQLALCHEMY_DATABASE_URL = "sqlite:///./users.db"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# User 모델 정의
class User(Base):
    __tablename__ = "user"
    
    id = Column(Integer, primary_key = True, index = True)
    username = Column(String, nullable = False)
    password = Column(String, nullable = False)


# 데이터베이스 테이블 생성
Base.metadata.create_all(bind=engine)

app = FastAPI()

# CORS 설정
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# 비밀번호 암호화 설정
# 아래 코드는 비밀번호를 해싱하는 방법을 정의합니다.
# pwd_context는 비밀번호를 검증하고 해싱하는 데 사용됩니다.
bcrypt_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# JWT 토큰 생성에 필요한 기본 설정값들
# 환경 변수 불러오기 위한 Class
class AppSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file='../.env',
        env_file_encoding='utf-8',
        extra='ignore',  # extra=forbid (default)
        frozen=True  # 값을 변경할 수 없도록 설정
    )
    
    SECRET_KEY: str = "secret_key"
    ALGORITHM: str = "algorithm"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 0

settings = AppSettings()

# OAuth2 인증 스키마 설정 - 토큰 엔드포인트 URL 지정
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Pydantic Model
class UserCreate(BaseModel):
    username: str
    password: str

# 토큰 응답 데이터 검증을 위한 Pydantic 모델
class Token(BaseModel):
    access_token: str  # JWT 토큰 문자열
    token_type: str  # Bearer

# 암호화된 비밀번호 반환
def get_password_hash(password):
    return bcrypt_context.hash(password)

# 비밀번호 검증
def verify_password(plain_password, hashed_password):
    return bcrypt_context.verify(plain_password, hashed_password)

# JWT 토큰 생성 함수
def create_token(username: str):
    # 만료 시간 설정
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    token_data = {"sub": username, "exp": expire}  # 토큰에 포함될 데이터
    return jwt.encode(token_data, settings.SECRET_KEY, algorithm=settings.ALGORITHM)  # JWT 토큰 생성

@app.post('/user/signup')
async def signup(user: UserCreate, db: Session = Depends(get_db)):
    check_user_in_db = db.query(User).filter(User.username == user.username).all()
    print(check_user_in_db)
    if check_user_in_db:  # 이미 존재하는 사용자인지 확인
        raise HTTPException(status_code=409, detail="Username already exists")
    
    # 사용자 정보 저장
    new_user = User(
        username = user.username,
        password = get_password_hash(user.password)
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return {"message": "User created successfully"}

@app.post('/user/login', response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # 유저 인증
    user = db.query(User).filter(User.username == form_data.username).first()
    verify_user = False if user is None else verify_password(form_data.password, user.password)
    
    if not verify_user: 
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    
    # 인증 성공시 JWT 토큰 생성 및 반환
    access_token = create_token(form_data.username)
    return {"access_token": access_token, "token_type": "bearer"}