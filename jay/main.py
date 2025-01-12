from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from pydantic import BaseModel  # 데이터 검증을 위한 Pydantic 모델
from sqlalchemy import create_engine, Column, Integer, String, Float, ForeignKey, DateTime, CheckConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship

from passlib.context import CryptContext
from pydantic_settings import BaseSettings, SettingsConfigDict
from fastapi.security import (
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm,
)  # OAuth2 인증 관련 클래스
from datetime import datetime, timezone, timedelta  # 시간 관련 처리를 위한 클래스
from jose import jwt, JWTError  # JWT 토큰 생성 및 검증을 위한 라이브러리

import httpx
import json
from typing import List, Dict

# Database 설정
SQLALCHEMY_DATABASE_URL = "sqlite:///./users.db"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# 모델 정의
class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    password = Column(String(255), nullable=False)  # 해시된 비밀번호 저장
    name = Column(String(100), nullable=False)
    age = Column(Integer, CheckConstraint('age >= 0 AND age <= 150'), nullable=False)
    gender = Column(String(1), CheckConstraint("gender IN ('M', 'F')"), nullable=False)
    height = Column(Float, CheckConstraint('height > 0'), nullable=False)
    weight = Column(Float, CheckConstraint('weight > 0'), nullable=False)
    created_at = Column(DateTime, default=datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))

    # Relationship
    questions = relationship("Question", back_populates="user", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User(username={self.username}, name={self.name})>"


class Question(Base):
    __tablename__ = 'questions'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    exercise_count = Column(Integer, CheckConstraint('exercise_count >= 0'), nullable=False)
    health_management_purpose = Column(String(100), nullable=False)
    detailed_goal = Column(String(500))
    created_at = Column(DateTime, default=datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))

    # Relationships
    user = relationship("User", back_populates="questions")
    health = relationship("Health", back_populates="question", uselist=False, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Question(user_id={self.user_id}, purpose={self.health_management_purpose})>"


class Health(Base):
    __tablename__ = 'health'

    id = Column(Integer, primary_key=True)
    question_id = Column(Integer, ForeignKey('questions.id', ondelete='CASCADE'), unique=True, nullable=False)
    profile_summary = Column(String(1000), nullable=False)
    health_management_routine = Column(String(2000), nullable=False)
    additional_tip = Column(String(1000))
    created_at = Column(DateTime, default=datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    
    # Relationship
    question = relationship("Question", back_populates="health")
    
    def __repr__(self):
        return f"<Health(question_id={self.question_id})>"


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

# 유저 정보를 담기 위한 dict
fake_users_db = {}

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
    name: str
    age: int
    gender: str # 'M' or 'F'
    height: float
    weight: float

# 토큰 응답 데이터 검증을 위한 Pydantic 모델
class Token(BaseModel):
    access_token: str  # JWT 토큰 문자열
    token_type: str  # Bearer

class TokenData(BaseModel):
    username: str | None = None

# 질문 생성 모델
class QuestionCreate(BaseModel):
    exercise_count: int
    health_management_purpose: str
    detailed_goal: str | None = None

# 암호화된 비밀번호 반환
def get_password_hash(password):
    return bcrypt_context.hash(password)

# 유저 정보 가져오기
def get_user(username: str, db: Session = next(get_db())):
    user_db = db.query(User).filter(User.username == username).first()
    if not user_db is None:
        return user_db

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

# Token을 통해서 현재 유저 정보 가져오기
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)

    except JWTError:
        raise credentials_exception
    
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    
    return user

@app.post('/user/signup')
async def signup(user: UserCreate, db: Session = Depends(get_db)):
    check_user_in_db = db.query(User).filter(User.username == user.username).all()
    print(check_user_in_db)
    if check_user_in_db:  # 이미 존재하는 사용자인지 확인
        raise HTTPException(status_code=409, detail="Username already exists")
    
    # 사용자 정보 저장
    new_user = User(
        username = user.username,
        password = get_password_hash(user.password),
        name = user.name,
        age = user.age,
        gender = user.gender,
        height = user.height,
        weight = user.weight,
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

class QuestionContent(BaseModel):
    question_content: str

class Message(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    messages: List[Message]

class ChatResponse(BaseModel):
    choices: List[Dict]
    created: int
    id: str
    model: str
    object: str
    usage: Dict


AIURL = "https://open-api.jejucodingcamp.workers.dev/"

@app.post('/chat', response_model=ChatResponse)
async def chat_endpoint(question_content: QuestionContent):
    user_data = [  # 직접 배열로 전송
        {
            "role": "system",
            "content": "assistant는 건강 관리 루틴을 잘 제시해주고, 식단 을 잘 추천해주는 헬스 트레이너야!\n\n답변은 1.프로필 분석, 2. 건강 관리 루틴과 추천 식단, 3. 추천 팁 이렇게 나누어서 출력해줘\n1번은 user가 준 정보를 통해서 운동 목적을 통해서 프로필을 분석해줘. 구체적인 목표가 있다면 더 구체적으로 분석해줘.\n2번은 건강 관리 루틴과 식단은 일차 별(Day1, Day2...)로 건강 관리 루틴 -> 식단 순서로 추천해줘. 표로 만들어주면 좋겠어.\n3번은 실생활에서 건강을 위한 팁들을 알려주면 좋겠어\n 그리고 각각 1번 2번 3번 앞에 ###을 배치함으로써 구분이 가능하게 해줘."
        },
        {
            "role": "user",
            "content": question_content.question_content
        }
    ]
    
    try:
        async with httpx.AsyncClient() as client:
            # 요청 직전의 데이터 출력
            print("Sending request with data:")
            print(json.dumps(user_data, ensure_ascii=False, indent=2))
            timeout = httpx.Timeout(10.0, read=None)

            response = await client.post(
                AIURL,
                headers={
                    "Content-Type": "application/json",
                },
                json=user_data,
                timeout=timeout
            )
            
            # 응답 상세 정보 출력
            print(f"Response status: {response.status_code}")
            print(f"Response headers: {response.headers}")
            print(f"Response content: {response.text}")
            
            if response.status_code == 200:
                response_data = response.json()
                print(f"Parsed response data: {json.dumps(response_data, ensure_ascii=False, indent=2)}")
                return ChatResponse(**response_data)
            else:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"API call failed: {response.text}"
                )
                
    except Exception as e:
        print(f"Error type: {type(e)}")
        print(f"Error message: {str(e)}")
        print(f"Error details: {getattr(e, '__dict__', {})}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )
        
@app.post('/healthmate')
async def get_health_info(question: QuestionCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # 성별 변환
    gender: str = "남자" if current_user.gender == "M" else "여자"
    
    # 질문 내용 구성
    question_content = (
        f"저의 프로필은 이름은 {current_user.name}이고, 나이는 {current_user.age}살, "
        f"키는 {current_user.height}cm이고 몸무게는 {current_user.weight}kg, 성별은 {gender}야. "
        f"운동 목적은 {question.health_management_purpose}이고, "
        f"운동 가능한 횟수는 일주일에 {question.exercise_count}번이야."
    )
    
    if question.detailed_goal:
        question_content += f" 구체적인 목표는 {question.detailed_goal}이야."
    
    try:
        # 질문 데이터베이스 저장
        new_question = Question(
            user_id=current_user.id,
            exercise_count=question.exercise_count,
            health_management_purpose=question.health_management_purpose,
            detailed_goal=question.detailed_goal,
        )
        db.add(new_question)
        db.commit()
        db.refresh(new_question)
        
        # AI 응답 요청
        content = QuestionContent(question_content=question_content)
        response = await chat_endpoint(content)
        
        if not response or not response.choices:
            raise HTTPException(status_code=500, detail="Invalid AI response format")
            
        # AI 응답 파싱 및 저장
        ai_message = response.choices[0]["message"]["content"]
        
        # Health 정보 저장
        health_info = Health(
            question_id=new_question.id,
            profile_summary=ai_message.split('###')[1],  # 실제로는 AI 응답을 적절히 파싱해야 합니다
            health_management_routine=ai_message.split('###')[2],
            additional_tip=ai_message.split('###')[3]
        )
        db.add(health_info)
        db.commit()
        
        return {"message": ai_message}
        
    except Exception as e:
        db.rollback()  # 에러 발생 시 트랜잭션 롤백
        print(f"Error in get_health_info: {str(e)}")  # 로깅 추가
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )