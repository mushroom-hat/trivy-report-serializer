from sqlalchemy.orm import Session
from sqlalchemy import or_
from models import Project, CveFinding, Image, ProjectStatus, StatusLevel
from datetime import datetime

def calculate_status(published_at, last_seen_at):
  """Return Low/Medium/High based on CVE age (days)."""
  age_days = (last_seen_at - published_at).days
  if age_days < 30:
      return StatusLevel.LOW
  elif 30 <= age_days < 90:
      return StatusLevel.MEDIUM
  else:
      return StatusLevel.HIGH
    
def get_or_create_project(db: Session, image_path: str):
  """
  Ensure the project exists in DB. Return the Project object.
  
  image_path format: <team>/<project>/<image>
  """
  parts = image_path.split("/", 2)
  team, project_name = parts[0], parts[1]

  project = db.query(Project).filter_by(team=team, project=project_name).first()
  if not project:
      project = Project(team=team, project=project_name)
      db.add(project)
      db.flush()  # flush to assign id
  return project

def update_project_status(db, project_id):
  """
  Calculate project status based on CVEs from the latest images
  (latest per path) for the project.

  Insert a new ProjectStatus row ONLY if the status changed
  compared to the latest stored status.
  """

  # --- Subquery: latest image per (project_id, path)
  latest_images_subq = (
      db.query(Image.id.label("image_id"))
      .filter(Image.project_id == project_id)
      .order_by(
          Image.project_id,
          Image.path,
          Image.created_at.desc(),
      )
      .distinct(Image.project_id, Image.path)
      .subquery()
  )
  
  # --- CVEs from latest images only, only critical or high
  findings = (
      db.query(
          CveFinding.published_at,
          CveFinding.last_seen_at,
          CveFinding.severity,
      )
      .join(
          latest_images_subq,
          latest_images_subq.c.image_id == CveFinding.image_id,
      )
      .filter(
          CveFinding.justified == False,
          or_(
              CveFinding.severity.ilike("critical"),
              CveFinding.severity.ilike("high")
          )
      )
      .all()
  )

  # --- Compute worst-case status
  new_status = StatusLevel.LOW
  for finding in findings:
      cve_status = calculate_status(
          finding.published_at,
          finding.last_seen_at,
      )
      if cve_status == StatusLevel.HIGH:
          new_status = StatusLevel.HIGH
          break
      elif cve_status == StatusLevel.MEDIUM:
          new_status = StatusLevel.MEDIUM

  # --- Fetch latest stored project status
  latest_status = (
      db.query(ProjectStatus.status)
      .filter(ProjectStatus.project_id == project_id)
      .order_by(ProjectStatus.calculated_at.desc())
      .limit(1)
      .scalar()
  )

  # --- Insert only if status changed (or no previous status)
  if latest_status != new_status:
      ps = ProjectStatus(
          project_id=project_id,
          status=new_status,
          calculated_at=datetime.utcnow(),
      )
      db.add(ps)
      db.flush()
