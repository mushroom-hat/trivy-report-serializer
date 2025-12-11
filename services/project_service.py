from sqlalchemy.orm import Session
from models import Project

def get_or_create_project(db: Session, image_path: str):
    """
    Ensure the project exists in DB. Return the Project object.
    
    image_path format: <user>/<project>/<image>
    """
    parts = image_path.split("/", 2)
    user, project_name = parts[0], parts[1]

    project = db.query(Project).filter_by(user=user, project=project_name).first()
    if not project:
        project = Project(user=user, project=project_name)
        db.add(project)
        db.flush()  # flush to assign id
    return project
