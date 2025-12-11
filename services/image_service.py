from models import Image
from config import settings


def upsert_image(db, namespace: str, info: dict, project_id: int):
  '''
  Upsert an image record based on the provided info and namespace.
  '''
  image = (
      db.query(Image)
      .filter(
          Image.digest == info["digest"],
          Image.env == settings.env,
          Image.cluster == settings.cluster_name,
          Image.namespace == namespace,
      )
      .first()
  )

  if not image:
      image = Image(
          digest=info["digest"],
          path=info["path"],
          project_id=project_id,
          tag=info["tag"],
          registry=info["registry"],
          os_family=info["os_family"],
          os_name=info["os_name"],
          namespace=namespace,
          cluster=settings.cluster_name,
          env=settings.env,
      )
      db.add(image)
      db.flush()

  return image
