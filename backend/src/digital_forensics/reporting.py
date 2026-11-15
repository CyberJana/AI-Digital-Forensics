from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from digital_forensics.audit import record_case_audit
from digital_forensics.case_access import CaseAccess, get_case_access, require_case_roles
from digital_forensics.database import get_db_session
from digital_forensics.identity import AuthenticatedUser, get_authenticated_user, require_csrf
from digital_forensics.models import (
    AuditEvent,
    AcquisitionRecord,
    CaseAISummary,
    CaseFinding,
    CaseReport,
    CaseRole,
    CaseStatus,
    CustodyEvent,
    EvidenceItem,
    FindingReviewDecision,
    InvestigationCase,
    ReportReviewDecision,
)

router = APIRouter(tags=["case analysis and reporting"])
DatabaseSession = Annotated[Session, Depends(get_db_session)]
CurrentUser = Annotated[AuthenticatedUser, Depends(get_authenticated_user)]
CsrfProtected = Annotated[None, Depends(require_csrf)]


class CreateFindingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=200)
    narrative: str = Field(min_length=1, max_length=10_000)
    source_record_ids: list[UUID] = Field(min_length=1, max_length=50)


class ReviewDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["approved", "rejected"]
    notes: str | None = Field(default=None, max_length=2000)


class CreateReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=200)
    finding_ids: list[UUID] = Field(min_length=1, max_length=100)


def _require_case_writer(access: CaseAccess) -> None:
    if access.case.status != CaseStatus.OPEN:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Closed cases are read-only",
        )
    require_case_roles(access, {CaseRole.OWNER, CaseRole.EXAMINER})


def _source_records(
    db: Session,
    case_id: UUID,
    requested_ids: list[UUID],
) -> dict[str, dict[str, object]]:
    case = db.get(InvestigationCase, case_id)
    records: dict[str, dict[str, object]] = {}
    if case is not None and case.id in requested_ids:
        records[str(case.id)] = {
            "source_type": "case",
            "source_record_id": case.id,
            "case_number": case.case_number,
            "name": case.name,
            "description": case.description,
            "status": case.status.value,
            "created_at": case.created_at,
        }
    evidence_items = db.scalars(
        select(EvidenceItem)
        .where(
            EvidenceItem.case_id == case_id,
            EvidenceItem.id.in_(requested_ids),
        )
    ).all()
    for evidence in evidence_items:
        records[str(evidence.id)] = {
            "source_type": "evidence",
            "source_record_id": evidence.id,
            "evidence_number": evidence.evidence_number,
            "name": evidence.name,
            "description": evidence.description,
            "size_bytes": evidence.size_bytes,
            "media_type": evidence.media_type,
            "original_sha256": evidence.original_sha256,
            "created_at": evidence.created_at,
        }
    acquisitions = db.execute(
        select(AcquisitionRecord, EvidenceItem)
        .join(EvidenceItem, EvidenceItem.id == AcquisitionRecord.evidence_id)
        .where(
            EvidenceItem.case_id == case_id,
            AcquisitionRecord.id.in_(requested_ids),
        )
    ).all()
    for acquisition, evidence in acquisitions:
        records[str(acquisition.id)] = {
            "source_type": "acquisition",
            "source_record_id": acquisition.id,
            "event_type": "acquisition",
            "occurred_at": _as_utc(acquisition.acquired_at),
            "recorded_at": _as_utc(acquisition.recorded_at),
            "evidence_id": evidence.id,
            "evidence_number": evidence.evidence_number,
            "actor_id": acquisition.acquired_by,
            "details": {
                "acquisition_method": acquisition.acquisition_method,
                "source_description": acquisition.source_description,
            },
            "notes": None,
        }
    custody_events = db.execute(
        select(CustodyEvent, EvidenceItem)
        .join(EvidenceItem, EvidenceItem.id == CustodyEvent.evidence_id)
        .where(
            EvidenceItem.case_id == case_id,
            CustodyEvent.id.in_(requested_ids),
        )
    ).all()
    for event, evidence in custody_events:
        records[str(event.id)] = {
            "source_type": "custody",
            "source_record_id": event.id,
            "event_type": event.event_type,
            "occurred_at": _as_utc(event.recorded_at),
            "recorded_at": _as_utc(event.recorded_at),
            "evidence_id": evidence.id,
            "evidence_number": evidence.evidence_number,
            "actor_id": event.actor_id,
            "details": event.details,
            "notes": event.notes,
        }
    summaries = db.scalars(
        select(CaseAISummary)
        .where(
            CaseAISummary.case_id == case_id,
            CaseAISummary.id.in_(requested_ids),
        )
    ).all()
    for summary in summaries:
        records[str(summary.id)] = {
            "source_type": "ai_summary",
            "source_record_id": summary.id,
            "summary": summary.summary,
            "review_status": summary.review_status,
            "summary_source_record_ids": summary.summary_source_record_ids,
            "key_points": summary.key_points,
            "created_at": summary.created_at,
        }
    return {
        source_id: jsonable_encoder(record)
        for source_id, record in records.items()
    }


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _latest_finding_decision(
    db: Session,
    finding_id: UUID,
) -> FindingReviewDecision | None:
    return db.scalar(
        select(FindingReviewDecision)
        .where(FindingReviewDecision.finding_id == finding_id)
        .order_by(FindingReviewDecision.created_at.desc(), FindingReviewDecision.id.desc())
        .limit(1)
    )


def _finding_decisions(db: Session, finding_id: UUID) -> list[FindingReviewDecision]:
    return db.scalars(
        select(FindingReviewDecision)
        .where(FindingReviewDecision.finding_id == finding_id)
        .order_by(FindingReviewDecision.created_at, FindingReviewDecision.id)
    ).all()


def _report_decisions(db: Session, report_id: UUID) -> list[ReportReviewDecision]:
    return db.scalars(
        select(ReportReviewDecision)
        .where(ReportReviewDecision.report_id == report_id)
        .order_by(ReportReviewDecision.created_at, ReportReviewDecision.id)
    ).all()


def _decision_response(
    decision: FindingReviewDecision | ReportReviewDecision | None,
) -> dict[str, object] | None:
    if decision is None:
        return None
    return {
        "id": decision.id,
        "reviewer_id": decision.reviewer_id,
        "decision": decision.decision,
        "notes": decision.notes,
        "created_at": decision.created_at,
    }


def _finding_response(db: Session, finding: CaseFinding) -> dict[str, object]:
    return _finding_payload(finding, _finding_decisions(db, finding.id))


def _finding_payload(
    finding: CaseFinding,
    decisions: list[FindingReviewDecision],
) -> dict[str, object]:
    latest = decisions[-1] if decisions else None
    return {
        "id": finding.id,
        "case_id": finding.case_id,
        "created_by": finding.created_by,
        "title": finding.title,
        "narrative": finding.narrative,
        "source_record_ids": finding.source_record_ids,
        "source_snapshot": finding.source_snapshot,
        "review_status": latest.decision if latest else "unreviewed",
        "latest_review": _decision_response(latest),
        "review_history": [_decision_response(decision) for decision in decisions],
        "created_at": finding.created_at,
    }


def _report_response(db: Session, report: CaseReport) -> dict[str, object]:
    return _report_payload(report, _report_decisions(db, report.id))


def _report_payload(
    report: CaseReport,
    decisions: list[ReportReviewDecision],
) -> dict[str, object]:
    latest = decisions[-1] if decisions else None
    return {
        "id": report.id,
        "case_id": report.case_id,
        "created_by": report.created_by,
        "title": report.title,
        "body": report.body,
        "finding_ids": report.finding_ids,
        "source_snapshot": report.source_snapshot,
        "review_status": latest.decision if latest else "unreviewed",
        "latest_review": _decision_response(latest),
        "review_history": [_decision_response(decision) for decision in decisions],
        "created_at": report.created_at,
    }


def _finding_responses(
    db: Session,
    findings: list[CaseFinding],
) -> list[dict[str, object]]:
    if not findings:
        return []
    decisions_by_finding: dict[UUID, list[FindingReviewDecision]] = {}
    decisions = db.scalars(
        select(FindingReviewDecision)
        .where(FindingReviewDecision.finding_id.in_([item.id for item in findings]))
        .order_by(FindingReviewDecision.created_at, FindingReviewDecision.id)
    ).all()
    for decision in decisions:
        decisions_by_finding.setdefault(decision.finding_id, []).append(decision)
    return [
        _finding_payload(finding, decisions_by_finding.get(finding.id, []))
        for finding in findings
    ]


def _report_responses(
    db: Session,
    reports: list[CaseReport],
) -> list[dict[str, object]]:
    if not reports:
        return []
    decisions_by_report: dict[UUID, list[ReportReviewDecision]] = {}
    decisions = db.scalars(
        select(ReportReviewDecision)
        .where(ReportReviewDecision.report_id.in_([item.id for item in reports]))
        .order_by(ReportReviewDecision.created_at, ReportReviewDecision.id)
    ).all()
    for decision in decisions:
        decisions_by_report.setdefault(decision.report_id, []).append(decision)
    return [
        _report_payload(report, decisions_by_report.get(report.id, []))
        for report in reports
    ]


@router.get("/cases/{case_id}/search")
def search_case(
    case_id: UUID,
    db: DatabaseSession,
    current: CurrentUser,
    q: str = Query(min_length=2, max_length=200),
    limit: int = Query(default=30, ge=1, le=100),
) -> list[dict[str, object]]:
    get_case_access(db, current.user.id, case_id)
    normalized_query = q.strip()
    if len(normalized_query) < 2:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Search terms must contain at least two non-space characters",
        )
    needle = f"%{normalized_query}%"
    hits: list[dict[str, object]] = []
    case = db.get(InvestigationCase, case_id)
    if case is not None and any(
        value and normalized_query.casefold() in value.casefold()
        for value in (case.case_number, case.name, case.description)
    ):
        hits.append(
            {
                "source_type": "case",
                "source_record_id": str(case.id),
                "title": f"{case.case_number} · {case.name}",
                "excerpt": case.description or "",
                "occurred_at": case.created_at,
            }
        )

    evidence_items = db.scalars(
        select(EvidenceItem)
        .where(
            EvidenceItem.case_id == case_id,
            EvidenceItem.evidence_number.ilike(needle)
            | EvidenceItem.name.ilike(needle)
            | EvidenceItem.description.ilike(needle),
        )
        .limit(limit)
    ).all()
    hits.extend(
        {
            "source_type": "evidence",
            "source_record_id": str(item.id),
            "title": f"{item.evidence_number} · {item.name}",
            "excerpt": item.description or "",
            "occurred_at": item.created_at,
        }
        for item in evidence_items
    )

    acquisition_rows = db.execute(
        select(AcquisitionRecord, EvidenceItem)
        .join(EvidenceItem, EvidenceItem.id == AcquisitionRecord.evidence_id)
        .where(
            EvidenceItem.case_id == case_id,
            or_(
                AcquisitionRecord.acquisition_method.ilike(needle),
                AcquisitionRecord.source_description.ilike(needle),
                EvidenceItem.evidence_number.ilike(needle),
            ),
        )
        .order_by(AcquisitionRecord.acquired_at.desc())
        .limit(limit)
    ).all()
    hits.extend(
        {
            "source_type": "acquisition",
            "source_record_id": str(record.id),
            "title": f"{evidence.evidence_number} · Acquisition",
            "excerpt": f"{record.acquisition_method} · {record.source_description}",
            "occurred_at": record.acquired_at,
        }
        for record, evidence in acquisition_rows
    )

    custody_rows = db.execute(
        select(CustodyEvent, EvidenceItem)
        .join(EvidenceItem, EvidenceItem.id == CustodyEvent.evidence_id)
        .where(
            EvidenceItem.case_id == case_id,
            or_(
                CustodyEvent.event_type.ilike(needle),
                CustodyEvent.notes.ilike(needle),
                EvidenceItem.evidence_number.ilike(needle),
            ),
        )
        .order_by(CustodyEvent.recorded_at.desc())
        .limit(limit)
    ).all()
    hits.extend(
        {
            "source_type": "custody",
            "source_record_id": str(event.id),
            "title": f"{evidence.evidence_number} · {event.event_type}",
            "excerpt": event.notes or event.event_type,
            "occurred_at": event.recorded_at,
        }
        for event, evidence in custody_rows
    )

    findings = db.scalars(
        select(CaseFinding)
        .where(
            CaseFinding.case_id == case_id,
            CaseFinding.title.ilike(needle) | CaseFinding.narrative.ilike(needle),
        )
        .limit(limit)
    ).all()
    hits.extend(
        {
            "source_type": "finding",
            "source_record_id": str(item.id),
            "title": item.title,
            "excerpt": item.narrative[:240],
            "occurred_at": item.created_at,
        }
        for item in findings
    )

    reports = db.scalars(
        select(CaseReport)
        .where(
            CaseReport.case_id == case_id,
            CaseReport.title.ilike(needle) | CaseReport.body.ilike(needle),
        )
        .limit(limit)
    ).all()
    hits.extend(
        {
            "source_type": "report",
            "source_record_id": str(item.id),
            "title": item.title,
            "excerpt": item.body[:240],
            "occurred_at": item.created_at,
        }
        for item in reports
    )

    summaries = db.scalars(
        select(CaseAISummary)
        .where(CaseAISummary.case_id == case_id, CaseAISummary.summary.ilike(needle))
        .limit(limit)
    ).all()
    hits.extend(
        {
            "source_type": "ai_summary",
            "source_record_id": str(item.id),
            "title": "AI summary (unreviewed)",
            "excerpt": item.summary[:240],
            "occurred_at": item.created_at,
        }
        for item in summaries
    )
    hits.sort(key=lambda hit: str(hit["occurred_at"]), reverse=True)
    return jsonable_encoder(hits[:limit])


@router.post(
    "/cases/{case_id}/findings",
    status_code=status.HTTP_201_CREATED,
)
def create_finding(
    case_id: UUID,
    payload: CreateFindingRequest,
    db: DatabaseSession,
    current: CurrentUser,
    _: CsrfProtected,
) -> dict[str, object]:
    access = get_case_access(db, current.user.id, case_id)
    _require_case_writer(access)
    source_ids = [str(source_id) for source_id in payload.source_record_ids]
    if len(set(source_ids)) != len(source_ids):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Source record IDs must be unique",
        )
    sources = _source_records(db, case_id, payload.source_record_ids)
    missing_sources = [source_id for source_id in source_ids if source_id not in sources]
    if missing_sources:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="All citations must refer to records in this case",
        )

    finding = CaseFinding(
        case_id=case_id,
        created_by=current.user.id,
        title=payload.title,
        narrative=payload.narrative,
        source_record_ids=source_ids,
        source_snapshot={"sources": [sources[source_id] for source_id in source_ids]},
    )
    db.add(finding)
    db.flush()
    record_case_audit(
        db,
        case_id=case_id,
        actor_id=current.user.id,
        action="finding.created",
        target_type="finding",
        target_id=finding.id,
        metadata={"source_count": len(source_ids)},
    )
    db.commit()
    db.refresh(finding)
    return _finding_response(db, finding)


@router.get("/cases/{case_id}/findings")
def list_findings(
    case_id: UUID,
    db: DatabaseSession,
    current: CurrentUser,
    limit: int = Query(default=100, ge=1, le=200),
) -> list[dict[str, object]]:
    get_case_access(db, current.user.id, case_id)
    findings = db.scalars(
        select(CaseFinding)
        .where(CaseFinding.case_id == case_id)
        .order_by(CaseFinding.created_at.desc(), CaseFinding.id)
        .limit(limit)
    ).all()
    return _finding_responses(db, findings)


@router.post(
    "/cases/{case_id}/findings/{finding_id}/reviews",
    status_code=status.HTTP_201_CREATED,
)
def review_finding(
    case_id: UUID,
    finding_id: UUID,
    payload: ReviewDecisionRequest,
    db: DatabaseSession,
    current: CurrentUser,
    _: CsrfProtected,
) -> dict[str, object]:
    access = get_case_access(db, current.user.id, case_id)
    require_case_roles(access, {CaseRole.REVIEWER})
    finding = db.get(CaseFinding, finding_id)
    if finding is None or finding.case_id != case_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    if finding.created_by == current.user.id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Authors cannot review their own findings",
        )
    decision = FindingReviewDecision(
        finding_id=finding.id,
        reviewer_id=current.user.id,
        decision=payload.decision,
        notes=payload.notes,
    )
    db.add(decision)
    db.flush()
    record_case_audit(
        db,
        case_id=case_id,
        actor_id=current.user.id,
        action=f"finding.{payload.decision}",
        target_type="finding",
        target_id=finding.id,
    )
    db.commit()
    db.refresh(decision)
    return {
        "id": decision.id,
        "finding_id": finding.id,
        "reviewer_id": decision.reviewer_id,
        "decision": decision.decision,
        "notes": decision.notes,
        "created_at": decision.created_at,
    }


@router.get("/cases/{case_id}/findings/{finding_id}/reviews")
def list_finding_reviews(
    case_id: UUID,
    finding_id: UUID,
    db: DatabaseSession,
    current: CurrentUser,
) -> list[dict[str, object]]:
    get_case_access(db, current.user.id, case_id)
    finding = db.get(CaseFinding, finding_id)
    if finding is None or finding.case_id != case_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return [_decision_response(item) for item in _finding_decisions(db, finding_id)]


@router.post(
    "/cases/{case_id}/reports",
    status_code=status.HTTP_201_CREATED,
)
def create_report(
    case_id: UUID,
    payload: CreateReportRequest,
    db: DatabaseSession,
    current: CurrentUser,
    _: CsrfProtected,
) -> dict[str, object]:
    access = get_case_access(db, current.user.id, case_id)
    _require_case_writer(access)
    requested_ids = [str(finding_id) for finding_id in payload.finding_ids]
    if len(set(requested_ids)) != len(requested_ids):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Finding IDs must be unique",
        )
    findings = db.scalars(
        select(CaseFinding).where(
            CaseFinding.case_id == case_id,
            CaseFinding.id.in_(payload.finding_ids),
        )
    ).all()
    findings_by_id = {str(finding.id): finding for finding in findings}
    if len(findings_by_id) != len(requested_ids):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="All findings must belong to this case",
        )
    ordered_findings = [findings_by_id[finding_id] for finding_id in requested_ids]
    snapshot = [
        {
            "id": finding.id,
            "title": finding.title,
            "narrative": finding.narrative,
            "source_record_ids": finding.source_record_ids,
            "source_snapshot": finding.source_snapshot,
            "review": _decision_response(_latest_finding_decision(db, finding.id)),
        }
        for finding in ordered_findings
    ]
    body = "\n\n".join(
        [
            f"# {payload.title}",
            f"Case: {access.case.case_number} — {access.case.name}",
            "Review status is tracked separately through append-only decisions.",
            *[
                f"## {finding.title}\n\n{finding.narrative}\n\nSources: "
                + ", ".join(finding.source_record_ids)
                for finding in ordered_findings
            ],
        ]
    )
    report = CaseReport(
        case_id=case_id,
        created_by=current.user.id,
        title=payload.title,
        body=body,
        finding_ids=requested_ids,
        source_snapshot={
            "case": {
                "id": str(access.case.id),
                "case_number": access.case.case_number,
                "name": access.case.name,
                "status": access.case.status.value,
                "created_at": jsonable_encoder(access.case.created_at),
            },
            "findings": jsonable_encoder(snapshot),
        },
    )
    db.add(report)
    db.flush()
    record_case_audit(
        db,
        case_id=case_id,
        actor_id=current.user.id,
        action="report.created",
        target_type="report",
        target_id=report.id,
        metadata={"finding_count": len(requested_ids)},
    )
    db.commit()
    db.refresh(report)
    return _report_response(db, report)


@router.get("/cases/{case_id}/reports")
def list_reports(
    case_id: UUID,
    db: DatabaseSession,
    current: CurrentUser,
    limit: int = Query(default=100, ge=1, le=200),
) -> list[dict[str, object]]:
    get_case_access(db, current.user.id, case_id)
    reports = db.scalars(
        select(CaseReport)
        .where(CaseReport.case_id == case_id)
        .order_by(CaseReport.created_at.desc(), CaseReport.id)
        .limit(limit)
    ).all()
    return _report_responses(db, reports)


@router.post(
    "/cases/{case_id}/reports/{report_id}/reviews",
    status_code=status.HTTP_201_CREATED,
)
def review_report(
    case_id: UUID,
    report_id: UUID,
    payload: ReviewDecisionRequest,
    db: DatabaseSession,
    current: CurrentUser,
    _: CsrfProtected,
) -> dict[str, object]:
    access = get_case_access(db, current.user.id, case_id)
    require_case_roles(access, {CaseRole.REVIEWER})
    report = db.get(CaseReport, report_id)
    if report is None or report.case_id != case_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    if report.created_by == current.user.id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Authors cannot review their own reports",
        )
    decision = ReportReviewDecision(
        report_id=report.id,
        reviewer_id=current.user.id,
        decision=payload.decision,
        notes=payload.notes,
    )
    db.add(decision)
    db.flush()
    record_case_audit(
        db,
        case_id=case_id,
        actor_id=current.user.id,
        action=f"report.{payload.decision}",
        target_type="report",
        target_id=report.id,
    )
    db.commit()
    db.refresh(decision)
    return {
        "id": decision.id,
        "report_id": report.id,
        "reviewer_id": decision.reviewer_id,
        "decision": decision.decision,
        "notes": decision.notes,
        "created_at": decision.created_at,
    }


@router.get("/cases/{case_id}/reports/{report_id}/reviews")
def list_report_reviews(
    case_id: UUID,
    report_id: UUID,
    db: DatabaseSession,
    current: CurrentUser,
) -> list[dict[str, object]]:
    get_case_access(db, current.user.id, case_id)
    report = db.get(CaseReport, report_id)
    if report is None or report.case_id != case_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    return [_decision_response(item) for item in _report_decisions(db, report_id)]


@router.get("/cases/{case_id}/audit-log")
def list_case_audit_log(
    case_id: UUID,
    db: DatabaseSession,
    current: CurrentUser,
    limit: int = Query(default=100, ge=1, le=500),
) -> list[dict[str, object]]:
    get_case_access(db, current.user.id, case_id)
    events = db.scalars(
        select(AuditEvent)
        .where(AuditEvent.case_id == case_id)
        .order_by(AuditEvent.occurred_at.desc(), AuditEvent.id)
        .limit(limit)
    ).all()
    return [
        {
            "id": event.id,
            "case_id": event.case_id,
            "actor_id": event.actor_id,
            "action": event.action,
            "target_type": event.target_type,
            "target_id": event.target_id,
            "metadata": event.metadata_json,
            "occurred_at": event.occurred_at,
        }
        for event in events
    ]
