from fastapi import APIRouter, Request, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from database import SessionLocal
from services.image_service import upsert_image
from services.cve_service import upsert_finding, create_detection
from services.project_service import get_or_create_project
from utils.parsing import parse_image_info

router = APIRouter()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/trivy-webhook")
async def trivy_webhook(request: Request, db: Session = Depends(get_db)):
    body = await request.json()

    # Identify the payload kind
    kind = body.get("kind") or body.get("report", {}).get("kind")

    if kind == "VulnerabilityReport":
        return await handle_vulnerability_report(body, db)

    return JSONResponse(
        status_code=400,
        content={"error": f"Unsupported report type: {kind}"}
    )

async def handle_vulnerability_report(body: dict, db: Session):
    namespace = body.get("metadata", {}).get("namespace")
    image_info = parse_image_info(body)
    update_ts = body["report"].get("updateTimestamp")
    scanner_version = body.get("scanner", {}).get("version")
    vulns = body["report"].get("vulnerabilities", [])

    # Get project from image path
    project = get_or_create_project(db, image_info["path"])

    # Upsert image
    image = upsert_image(
        db,
        namespace=namespace,
        image_info=image_info,
        project_id=project.id
    )

    # Upsert CVE findings
    for v in vulns:
        finding = upsert_finding(db, image.id, v, update_ts)
        create_detection(db, finding.id, scanner_version)

    db.commit()
    report_name = body.get("metadata", {}).get("name", "unknown")
    return {"status": "ok", "message": f"VulnerabilityReport {report_name} ingested."}