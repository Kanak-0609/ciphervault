import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, LargeBinary
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
from urllib.parse import quote_plus

load_dotenv()  # reads variables from the .env file into the environment

Base = declarative_base()


class KeyRecord(Base):
    __tablename__ = "keys"
    id = Column(Integer, primary_key=True)
    key_id = Column(String(100), unique=True)
    wrapped_key = Column(LargeBinary)  # the Fernet key, encrypted with our RSA public key
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)  # optional expiry
    revoked = Column(Boolean, default=False)


class AccessLog(Base):
    __tablename__ = "access_logs"
    id = Column(Integer, primary_key=True)
    key_id = Column(String(100))
    action = Column(String(50))  # "generate", "encrypt", "decrypt", "revoke", "denied"
    detail = Column(String(255), nullable=True)  # e.g. reason for a denial
    timestamp = Column(DateTime, default=datetime.utcnow)


from urllib.parse import quote_plus

mysql_password = quote_plus(os.getenv("MYSQL_PASSWORD"))
engine = create_engine(f"mysql+pymysql://root:{mysql_password}@localhost/ciphervault")
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)