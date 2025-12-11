from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from datetime import datetime
import os
from config import settings

# DB URL can be set via environment variable
DATABASE_URL = settings.database_url

# SQLAlchemy engine
engine = create_engine(DATABASE_URL, echo=False)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for ORM models
Base = declarative_base()

# Optional: create tables if they don't exist
def init_db():
    import models  # import all your models
    Base.metadata.create_all(bind=engine)
