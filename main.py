from fastapi import FastAPI, Request, Depends
from fastapi.responses import JSONResponse
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from database import SessionLocal
from models import *

app = FastAPI()
CLUSTER_NAME = "site_1"
ENV="stg"
SLA_DAYS = 90

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.post("/trivy-webhook")
async def trivy_webhook(
    request: Request,
    db: Session = Depends(get_db),
):
    body = await request.json()
    namespace = body.get("metadata", {}).get("namespace")
    if not namespace:
        return JSONResponse({"error": "namespace missing"}, status_code=400)
    
    metadata = body["metadata"]
    report = body["report"]
    vulns = report.get("vulnerabilities", [])
    

    # Extract image details
    artifact = report["artifact"]
    image_digest = artifact["digest"]
    image_repo = artifact["repository"]
    image_tag = artifact.get("tag", "latest")
    registry_server = body["report"]["registry"]["server"]
    
    # --- Upsert image ---
    image = (
        db.query(Image)
        .filter(
            Image.digest == image_digest,
            Image.env == ENV,
            Image.cluster == CLUSTER_NAME,
            Image.namespace == namespace,
        )
        .first()
    )
    
    if not image:
        image = Image(
            digest=image_digest,
            path=image_repo,
            tag=image_tag,
            registry=registry_server,
            os_family=body["report"]["os"].get("family"),
            os_name=body["report"]["os"].get("name"),
            namespace=namespace,
            cluster=CLUSTER_NAME,
            env=ENV,
        )
        db.add(image)
        db.flush()

    now = datetime.utcnow()

    for v in vulns:
        published_raw = v.get("publishedDate")
        try:
            published_at = datetime.fromisoformat(published_raw.replace("Z", ""))
        except:
            published_at = now  # fallback if missing

        due_at = published_at + timedelta(days=SLA_DAYS)
        cve_id = v["vulnerabilityID"]
        purl = v.get("packagePURL") or "none"
        
        finding = (
            db.query(CveFinding)
            .filter(
                CveFinding.image_id == image.id,
                CveFinding.cve_id == cve_id,
                CveFinding.package_purl == purl,
            )
            .first()
        )

        if finding:
            finding.last_seen_at = report.get("updateTimestamp")
            finding.score = v.get("score", finding.score)
            finding.severity = v.get("severity", finding.severity).lower()

        else:
            finding = CveFinding(
                image_id=image.id,
                cve_id=cve_id,
                package_purl=purl,
                package_name=v.get("resource"),
                installed_ver=v.get("installedVersion"),
                fixed_ver=v.get("fixedVersion"),
                severity=v.get("severity", "unknown").lower(),
                score=v.get("score", 0),
                title=v.get("title", cve_id),
                primary_link=v.get("primaryLink"),
                links=v.get("links", []),
                target=v.get("target"),
                published_at=published_at,
                first_seen_at=report.get("updateTimestamp"),
                last_seen_at=report.get("updateTimestamp"),
                due_at=due_at,
            )
            db.add(finding)
            db.flush()

        # Add to detection history
        detection = CveDetection(
            finding_id=finding.id,
            detected_at=now,
            scanner_name="trivy",
            scanner_version=body.get("scanner", {}).get("version"),
        )
        db.add(detection)

    db.commit()

    return {"status": "ok", "namespace": namespace}