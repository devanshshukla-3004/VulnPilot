from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import func
from .database import Base, engine, get_db
from .models import Asset, Vulnerability, StatusHistory
from .schemas import AssetIn, ImportPayload, StatusUpdate
from .risk import calculate_risk, risk_label

Base.metadata.create_all(bind=engine)
app = FastAPI(title="VulnPilot API", version="0.1.0",
              description="Explainable vulnerability prioritization and remediation tracking.")

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "VulnPilot API"}

@app.post("/api/assets", status_code=201)
def create_asset(payload: AssetIn, db: Session = Depends(get_db)):
    if db.query(Asset).filter_by(asset_key=payload.asset_key).first():
        raise HTTPException(409, "asset_key already exists")
    asset = Asset(**payload.model_dump())
    db.add(asset); db.commit(); db.refresh(asset)
    return {"id": asset.id, "asset_key": asset.asset_key}

@app.post("/api/import/json")
def import_json(payload: ImportPayload, db: Session = Depends(get_db)):
    assets_added = 0
    findings_added = 0
    for item in payload.assets:
        if db.query(Asset).filter_by(asset_key=item.asset_key).first():
            continue
        db.add(Asset(**item.model_dump()))
        assets_added += 1
    db.flush()
    for item in payload.vulnerabilities:
        if db.query(Vulnerability).filter_by(finding_key=item.finding_key).first():
            continue
        asset = db.query(Asset).filter_by(asset_key=item.asset_key).first()
        if not asset:
            db.rollback()
            raise HTTPException(422, f"Unknown asset_key: {item.asset_key}")
        data = item.model_dump(exclude={"asset_key"})
        db.add(Vulnerability(**data, asset_id=asset.id))
        findings_added += 1
    db.commit()
    return {"assets_added": assets_added, "findings_added": findings_added}

def serialize_finding(v: Vulnerability):
    score, factors = calculate_risk(v.cvss, v.asset.criticality, v.asset.internet_exposed,
                                    v.exploit_available, v.status)
    return {"id": v.id, "finding_key": v.finding_key, "cve_id": v.cve_id,
            "title": v.title, "cvss": v.cvss, "exploit_available": v.exploit_available,
            "status": v.status, "description": v.description, "asset_key": v.asset.asset_key,
            "hostname": v.asset.hostname, "criticality": v.asset.criticality,
            "internet_exposed": v.asset.internet_exposed, "risk_score": score,
            "risk_label": risk_label(score), "risk_factors": factors}

@app.get("/api/assets")
def list_assets(db: Session = Depends(get_db)):
    return [{"id": a.id, "asset_key": a.asset_key, "hostname": a.hostname,
             "environment": a.environment, "criticality": a.criticality,
             "internet_exposed": a.internet_exposed,
             "vulnerability_count": len(a.vulnerabilities)} for a in db.query(Asset).options(joinedload(Asset.vulnerabilities)).all()]

@app.get("/api/findings")
def list_findings(status: str | None = None, db: Session = Depends(get_db)):
    query = db.query(Vulnerability).options(joinedload(Vulnerability.asset))
    if status:
        if status not in {"open", "in_progress", "resolved"}:
            raise HTTPException(422, "Invalid status filter")
        query = query.filter(Vulnerability.status == status)
    return sorted([serialize_finding(v) for v in query.all()],
                  key=lambda x: x["risk_score"], reverse=True)

@app.get("/api/summary")
def summary(db: Session = Depends(get_db)):
    findings = list_findings(db=db)
    return {"asset_count": db.query(func.count(Asset.id)).scalar() or 0,
            "finding_count": len(findings),
            "open_count": sum(f["status"] == "open" for f in findings),
            "critical_count": sum(f["risk_label"] == "critical" for f in findings),
            "high_count": sum(f["risk_label"] == "high" for f in findings),
            "resolved_count": sum(f["status"] == "resolved" for f in findings),
            "average_risk": round(sum(f["risk_score"] for f in findings) / len(findings), 1) if findings else 0}

@app.patch("/api/findings/{finding_id}/status")
def update_status(finding_id: int, payload: StatusUpdate, db: Session = Depends(get_db)):
    finding = db.query(Vulnerability).filter_by(id=finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    old = finding.status
    if old == "resolved" and payload.status != "resolved":
        raise HTTPException(409, "Resolved findings cannot be reopened in this MVP; create a follow-up finding.")
    if old != payload.status:
        finding.status = payload.status
        db.add(StatusHistory(vulnerability_id=finding.id, old_status=old,
                             new_status=payload.status, note=payload.note))
        db.commit()
    return {"id": finding.id, "old_status": old, "status": finding.status}

@app.get("/api/findings/{finding_id}/history")
def finding_history(finding_id: int, db: Session = Depends(get_db)):
    finding = db.query(Vulnerability).filter_by(id=finding_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    rows = db.query(StatusHistory).filter_by(vulnerability_id=finding_id).order_by(StatusHistory.changed_at).all()
    return [{"old_status": r.old_status, "new_status": r.new_status,
             "note": r.note, "changed_at": r.changed_at.isoformat()} for r in rows]
