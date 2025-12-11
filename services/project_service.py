from sqlalchemy.orm import Session
from models import Project

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
