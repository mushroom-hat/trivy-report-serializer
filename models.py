from sqlalchemy import Column, Integer, String, Text, Numeric, TIMESTAMP, ForeignKey, JSON
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

Base = declarative_base()


class Image(Base):
    __tablename__ = "images"

    id = Column(Integer, primary_key=True)
    digest = Column(Text, unique=True, nullable=False)
    path = Column(Text, nullable=False)
    tag = Column(Text, nullable=False)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    registry = Column(String)
    os_family = Column(String, nullable=True)
    os_name = Column(String, nullable=True)
    namespace = Column(Text)
    cluster = Column(Text)
    env = Column(Text)

class CveFinding(Base):
    __tablename__ = "cve_findings"

    id = Column(Integer, primary_key=True)
    image_id = Column(Integer, ForeignKey("images.id"), nullable=False)
    cve_id = Column(Text, nullable=False)
    package_purl = Column(Text, nullable=False)
    package_name = Column(Text)
    installed_ver = Column(Text, nullable=False)
    fixed_ver = Column(Text)
    severity = Column(String, nullable=False)
    score = Column(Numeric(3, 1), nullable=False)
    title = Column(Text, nullable=False)
    primary_link = Column(Text)
    published_at = Column(TIMESTAMP, nullable=False)
    first_seen_at = Column(TIMESTAMP, nullable=False)
    last_seen_at = Column(TIMESTAMP, nullable=False)
    due_at = Column(TIMESTAMP)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    links = Column(JSON, nullable=True)
    target = Column(String, nullable=True)


class CveDetection(Base):
    __tablename__ = "cve_detections"

    id = Column(Integer, primary_key=True)
    finding_id = Column(Integer, ForeignKey("cve_findings.id"), nullable=False)
    detected_at = Column(TIMESTAMP, nullable=False)
    scanner_name = Column(Text, nullable=False, default="trivy")
    scanner_version = Column(Text)
