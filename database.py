import os
from datetime import datetime
from typing import Optional

from sqlalchemy import create_engine, Column, String, Integer, Float, Boolean, Text, DateTime, JSON
from sqlalchemy.orm import declarative_base, sessionmaker

# Railway: DATABASE_URL (postgres://...), Neon/Supabase: same, Local: fallback to sqlite
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
# Railway Postgres addon provides DATABASE_URL, but also PG* vars
if not DATABASE_URL:
    # Try Railway's alternative vars
    DATABASE_URL = os.getenv("DATABASE_PRIVATE_URL", "").strip()

# Fallback to local SQLite file (persistent in container, but will be ignored on Railway ephemeral - use Postgres there)
if not DATABASE_URL:
    DATABASE_URL = "sqlite:///./penguard.db"
else:
    # Handle postgres:// vs postgresql:// for SQLAlchemy
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# For psycopg2, ensure we use postgresql://
engine_kwargs = {}
if DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}

try:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True, **engine_kwargs)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base = declarative_base()
    _db_available = True
except Exception as e:
    print(f"[database] engine creation failed, fallback to memory: {e}")
    engine = None
    SessionLocal = None
    Base = declarative_base()
    _db_available = False


class Episode(Base):
    __tablename__ = "episodes"

    id = Column(String, primary_key=True, index=True)
    target = Column(Text)
    attack_type = Column(String, index=True)
    attack_label = Column(String)
    status = Column(Integer)
    retest_status = Column(Integer, nullable=True)
    patch_applied = Column(Boolean)
    threat_flag = Column(Boolean)
    score = Column(Float)
    remediation = Column(Text)
    logs = Column(JSON)  # stored as JSON text on sqlite
    timestamp = Column(String)
    duration_ms = Column(Integer)
    scenario = Column(String, index=True)
    base_url = Column(Text)
    pr_url = Column(Text, nullable=True)
    recon_data = Column(JSON, nullable=True)
    detection_report = Column(JSON, nullable=True)
    hardening_plan = Column(JSON, nullable=True)
    response_body = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class PostureMetric(Base):
    __tablename__ = "posture_metrics"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    posture_score = Column(Float)
    total_episodes = Column(Integer)
    patched_count = Column(Integer)


def init_db():
    if not _db_available or engine is None:
        print("[database] init skipped - no engine")
        return False
    try:
        Base.metadata.create_all(bind=engine)
        print(f"[database] initialized: {DATABASE_URL.split('@')[-1][:30]}...")
        return True
    except Exception as e:
        print(f"[database] init failed: {e}")
        return False


def get_db():
    if SessionLocal is None:
        yield None
        return
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Try to init on import (best-effort, fails silently if DB not reachable)
try:
    init_db()
except Exception as e:
    print(f"[database] auto-init failed: {e}")
