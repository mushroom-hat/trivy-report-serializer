from datetime import datetime, timedelta
from models import CveFinding, CveDetection
from config import settings

def parse_published_date(raw):
    now = datetime.utcnow()
    if not raw:
        return now
    try:
        return datetime.fromisoformat(raw.replace("Z", ""))
    except:
        return now


def upsert_finding(db, image_id, vuln: dict, update_ts):
    '''
    Upsert a CVE finding based on the provided vulnerability data and image ID.
    '''
    published_at = parse_published_date(vuln.get("publishedDate"))
    due_at = published_at + timedelta(days=settings.sla_days)
    cve_id = vuln["vulnerabilityID"]
    purl = vuln.get("packagePURL") or "none"

    finding = (
        db.query(CveFinding)
        .filter(
            CveFinding.image_id == image_id,
            CveFinding.cve_id == cve_id,
            CveFinding.package_purl == purl,
        )
        .first()
    )

    if finding:
        finding.last_seen_at = update_ts
        finding.score = vuln.get("score", finding.score)
        finding.severity = vuln.get("severity", finding.severity).lower()

    else:
        finding = CveFinding(
            image_id=image_id,
            cve_id=cve_id,
            package_purl=purl,
            package_name=vuln.get("resource"),
            installed_ver=vuln.get("installedVersion"),
            fixed_ver=vuln.get("fixedVersion"),
            severity=vuln.get("severity", "unknown").lower(),
            score=vuln.get("score", 0),
            title=vuln.get("title", cve_id),
            primary_link=vuln.get("primaryLink"),
            links=vuln.get("links", []),
            target=vuln.get("target"),
            published_at=published_at,
            first_seen_at=update_ts,
            last_seen_at=update_ts,
            due_at=due_at,
        )
        db.add(finding)
        db.flush()

    return finding

def create_detection(db, finding_id, scanner_version):
    '''
    Create a CVE detection record for the given finding ID.
    '''
    detection = CveDetection(
        finding_id=finding_id,
        detected_at=datetime.utcnow(),
        scanner_name="trivy",
        scanner_version=scanner_version,
    )
    db.add(detection)
