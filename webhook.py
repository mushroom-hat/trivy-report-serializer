from fastapi import FastAPI, Request, Header
from fastapi.responses import JSONResponse
from datetime import datetime
import uvicorn
import json
import os

app = FastAPI()

SAVE_DIR = "./incoming_reports"
os.makedirs(SAVE_DIR, exist_ok=True)


@app.post("/trivy-webhook")
async def trivy_webhook(
    request: Request,
    x_report_type: str | None = Header(default=None),
    x_resource_namespace: str | None = Header(default=None),
    x_resource_name: str | None = Header(default=None),
):
    """
    Trivy Operator webhook receiver.

    Currently processes only VulnerabilityReports.
    Placeholder hooks for other report types (ConfigAudit, SBOM, etc.)
    """

    body = await request.json()

    kind = body.get("kind")
    if kind != "VulnerabilityReport":
        # Future: handle SBOM, ConfigAudit, etc.
        print(f"Ignoring report of kind {kind}")
        return JSONResponse(
            {"status": "ignored", "reason": f"kind={kind} not processed"},
            status_code=200
        )

    # Only process VulnerabilityReports
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"{timestamp}_{x_report_type or 'vulnerabilityreport'}.json"
    filepath = os.path.join(SAVE_DIR, filename)

    # Save the report
    with open(filepath, "w") as f:
        json.dump(body, f, indent=2)

    print("=== Incoming VulnerabilityReport ===")
    print("Type:", x_report_type)
    print("Namespace:", x_resource_namespace)
    print("Name:", x_resource_name)
    print("Saved to:", filepath)
    print("Payload:", json.dumps(body, indent=2))
    print("=============================")

    return JSONResponse(
        {"status": "ok", "saved_as": filename},
        status_code=200
    )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
