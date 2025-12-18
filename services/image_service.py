from models import Image, CveDetection, CveFinding
from config import settings


def insert_image(db, namespace: str, info: dict, project_id: int):
  '''
  Upsert an image record based on the provided info and namespace.
  '''
  # Try to find an existing image with the same path, tag, env, site, namespace
  image = (
      db.query(Image)
      .filter(
          Image.path == info["path"],
          Image.tag == info["tag"],
          Image.env == settings.env,
          Image.site == settings.site,
          Image.namespace == namespace,
      )
      .order_by(Image.created_at.desc())  # get latest if multiple exist
      .first()
  )

  # If no image exists, or digest is different, insert a new row
  if not image or image.digest != info["digest"]:
      image = Image(
          digest=info["digest"],
          path=info["path"],
          project_id=project_id,
          tag=info["tag"],
          registry=info.get("registry"),
          os_family=info.get("os_family"),
          os_name=info.get("os_name"),
          namespace=namespace,
          site=settings.site,
          env=settings.env,
      )
      db.add(image)
      db.flush()

  return image

def delete_old_images(db, project_id, path, keep_image_id):
  """
  Delete all images for a given project/path/tag except the one to keep.
  Also delete related CVE findings and detections.
  """
  # Get IDs of images to delete
  old_image_ids = (
      db.query(Image.id)
      .filter(
          Image.project_id == project_id,
          Image.path == path,
          Image.id != keep_image_id
      )
      .all()
  )
  old_image_ids = [i[0] for i in old_image_ids]

  if not old_image_ids:
      return

  # Delete CVE detections
  db.query(CveDetection).filter(
      CveDetection.finding_id.in_(
          db.query(CveFinding.id).filter(CveFinding.image_id.in_(old_image_ids))
      )
  ).delete(synchronize_session=False)

  # Delete CVE findings
  db.query(CveFinding).filter(CveFinding.image_id.in_(old_image_ids)).delete(
      synchronize_session=False
  )

  # Delete images
  db.query(Image).filter(Image.id.in_(old_image_ids)).delete(
      synchronize_session=False
  )

  db.flush()  # commit optional here if handled outside
