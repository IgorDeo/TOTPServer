from sqlalchemy import Column, String, DateTime
from .database import Base
import uuid


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, index=True)
    name = Column(String)
    totp_secret = Column(String, nullable=True)
    last_totp_use = Column(DateTime, nullable=True)
