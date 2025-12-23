from models import Image
from fastapi import APIRouter, Request, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
import httpx
import logging
import hmac

from config import settings
from database import SessionLocal
from services.image_service import insert_image, delete_old_images
from services.cve_service import upsert_finding, create_detection
from services.project_service import get_or_create_project, update_project_status
from utils.parsing import parse_image_info

router = APIRouter()
logger = logging.getLogger("trivy-webhook")

def get_db():
  db = SessionLocal()
  try:
      yield db
  finally:
      db.close()

@router.post("/trivy-webhook")
async def trivy_webhook(request: Request, db: Session = Depends(get_db)):
  try:
    # API key check for hub mode
    api_key = request.headers.get("X-API-KEY")
    if settings.mode == "hub":
      if not api_key or not hmac.compare_digest(api_key, settings.hub_api_key):
        logger.warning("Unauthorized request, invalid or missing API key")
        return JSONResponse(
          status_code=status.HTTP_401_UNAUTHORIZED,
          content={"error": "Invalid or missing API key"},
        )

    # Parse JSON body
    try:
        body = await request.json()
    except Exception as e:
      logger.error("Failed to parse JSON body: %s", e)
      return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"error": "Invalid JSON payload"},
      )

    # Identify payload kind
    kind = body.get("kind") or body.get("report", {}).get("kind")
    if kind != "VulnerabilityReport":
      logger.warning("Unsupported report type: %s", kind)
      return JSONResponse(
          status_code=status.HTTP_400_BAD_REQUEST,
          content={"error": f"Unsupported report type: {kind}"},
      )

      # Enrich the report
    enriched = await enrich_vulnerability_reports(body)

    # Hub vs Non-Hub behavior
    if settings.mode == "hub":
      result = await handle_vulnerability_report(enriched, db)
      return JSONResponse(status_code=200, content=result)
    else:
      await send_to_hub(enriched)
      return JSONResponse(
          status_code=200,
          content={"status": "forwarded to hub"}
      )

  except Exception as e:
    # Catch-all error
    logger.exception("Unexpected error processing trivy webhook: %s", e)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "Internal server error"},
    )
    
async def enrich_vulnerability_reports(body: dict):
  enriched = {
    **body,
    "metadata": {
      **body.get("metadata", {}),
      "site": settings.site,
      "env": settings.env,
    },
  }

  return enriched

async def send_to_hub(report: dict):
  hub_url = settings.hub_url.rstrip("/") + "/trivy-webhook"
  api_key = settings.hub_api_key

  headers = {
    "Content-Type": "application/json",
    "X-API-KEY": api_key,
  }

  async with httpx.AsyncClient() as client:
    response = await client.post(hub_url, json=report, headers=headers)
    response.raise_for_status()

async def handle_vulnerability_report(body: dict, db: Session):
  try:
    namespace = body.get("metadata", {}).get("namespace")
    image_info = parse_image_info(body)
    update_ts = body["report"].get("updateTimestamp")
    scanner_version = body.get("scanner", {}).get("version")
    vulns = body["report"].get("vulnerabilities", [])

    # Get project from image path
    project = get_or_create_project(db, image_info["path"])

    # Insert image
    image = insert_image(
      db,
      namespace=namespace,
      info=image_info,
      project_id=project.id
    )

    # Delete older images for same project/path
    delete_old_images(db, project.id, image_info["path"], image.id)

    # Upsert CVE findings
    for v in vulns:
      finding = upsert_finding(db, image.id, v, update_ts)
      create_detection(db, finding.id, scanner_version)

    # Recalculate project status
    project_id = db.query(Image.project_id).filter(Image.id == image.id).scalar()
    update_project_status(db, project_id)

    db.commit()
    report_name = body.get("metadata", {}).get("name", "unknown")
    return {"status": "ok", "message": f"VulnerabilityReport {report_name} ingested."}

  except SQLAlchemyError as e:
    db.rollback()
    logger.exception("Database error while processing VulnerabilityReport")
    return {"status": "error", "message": "Database error occurred."}

  except Exception as e:
    db.rollback()
    logger.exception("Unexpected error while processing VulnerabilityReport")
    return {"status": "error", "message": "Unexpected error occurred."}