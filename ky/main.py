from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import jwt
from typing import Optional
from passlib.context import CryptContext

app = FastAPI()

# OAuth2 설정
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# 비밀번호 해싱 설정
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT 설정
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# CORS 설정
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True, 
    allow_methods=["*"],
    allow_headers=["*"],
)

# 모델 정의
class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str

class User(UserBase):
    disabled: Optional[bool] = None

class Token(BaseModel):
    access_token: str
    token_type: str

# 임시 사용자 데이터베이스
fake_users_db = {
    "testuser": {
        "username": "testuser",
        "hashed_password": pwd_context.hash("testpass"),
        "disabled": False
    }
}

def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

def get_user(username: str):
    if username in fake_users_db:
        user_dict = fake_users_db[username]
        return User(**user_dict)
    return None

def authenticate_user(username: str, password: str):
    user_dict = fake_users_db.get(username)
    if not user_dict:
        return False
    if not verify_password(password, user_dict["hashed_password"]):
        return False
    return User(**user_dict)

# JWT 토큰 생성 함수
def create_token(username: str):
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)  # 만료 시간 설정
    token_data = {"sub": username, "exp": expire}  # 토큰에 포함될 데이터
    return jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)  # JWT 토큰 생성

# 현재 사용자 인증 함수 - 보호된 라우트에서 사용
async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        # JWT 토큰 디코딩 및 검증
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")  # 토큰에서 사용자 이름 추출
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except jwt.JWTError:  # JWT 토큰 검증 실패시
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = get_user(db, username)
    if user is None:
        raise credentials_exception
    return user

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_token(data={"sub": user.username})
    return Token(access_token=access_token, token_type="bearer")
    
    
@app.get("/users/me", response_model=User)
async def read_users_me(current_user: UserModel = Depends(get_current_user)):
    return current_user