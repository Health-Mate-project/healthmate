from sqlalchemy import Boolean, Column, String
from .database import Base

class UserModel(Base):
    __tablename__ = "users"

    username = Column(String, primary_key=True, index=True)
    hashed_password = Column(String)
    disabled = Column(Boolean, default=False)