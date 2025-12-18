from sqlalchemy import Column, Integer, String, Text, Numeric, TIMESTAMP, ForeignKey, JSON, Boolean, UniqueConstraint
from sqlalchemy.orm import declarative_base
from datetime import datetime
from enum import Enum

Base = declarative_base()

class StatusLevel(str, Enum):
    LOW = "green"
    MEDIUM = "amber"
    HIGH = "red"


class ProjectStatus(Base):
  __tablename__ = "project_status"

  id = Column(Integer, primary_key=True, autoincrement=True)

  # One-to-one with Project
  project_id = Column(
      Integer,
      ForeignKey("projects.id", ondelete="CASCADE"),
      nullable=False,
      unique=True,
  )

  # Overall project CVE health
  # low = green, medium = amber, high = red
  status = Column(String, nullable=False)

  # When this status was last computed
  calculated_at = Column(
      TIMESTAMP(timezone=True),
      nullable=False,
      default=datetime.utcnow,
  )

class Project(Base):
  __tablename__ = "projects"

  id = Column(Integer, primary_key=True, autoincrement=True)
  team = Column(Text, nullable=False)
  project = Column(Text, nullable=False)
  created_at = Column(TIMESTAMP(timezone=True), default=datetime.utcnow)

  __table_args__ = (
      UniqueConstraint("team", "project", name="uq_team_project"),
  )


class Image(Base):
  __tablename__ = "images"

  id = Column(Integer, primary_key=True)
  digest = Column(Text, nullable=False)
  path = Column(Text, nullable=False)
  project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
  tag = Column(Text, nullable=False)
  created_at = Column(TIMESTAMP(timezone=True), default=datetime.utcnow)
  registry = Column(Text)
  os_family = Column(Text, nullable=True)
  os_name = Column(Text, nullable=True)
  namespace = Column(Text)
  site = Column(Text)
  env = Column(Text)


class CveFinding(Base):
  __tablename__ = "cve_findings"

  id = Column(Integer, primary_key=True)
  image_id = Column(Integer, ForeignKey("images.id", ondelete="CASCADE"), nullable=False)
  cve_id = Column(Text)
  package_purl = Column(Text)
  package_name = Column(Text)
  installed_ver = Column(Text)
  fixed_ver = Column(Text)
  severity = Column(String)
  score = Column(Numeric(3, 1))
  title = Column(Text)
  primary_link = Column(Text)
  published_at = Column(TIMESTAMP(timezone=True), nullable=False)
  first_seen_at = Column(TIMESTAMP(timezone=True), nullable=False)
  last_seen_at = Column(TIMESTAMP(timezone=True), nullable=False)
  due_at = Column(TIMESTAMP(timezone=True), nullable=False)
  created_at = Column(TIMESTAMP(timezone=True), default=datetime.utcnow)
  links = Column(JSON, nullable=True)
  target = Column(Text)
  justified = Column(Boolean, default=False)


class CveDetection(Base):
  __tablename__ = "cve_detections"

  id = Column(Integer, primary_key=True)
  finding_id = Column(Integer, ForeignKey("cve_findings.id", ondelete="CASCADE"), nullable=False)
  detected_at = Column(TIMESTAMP(timezone=True), nullable=False)
  scanner_name = Column(Text, default="trivy", nullable=False)
  scanner_version = Column(Text)
