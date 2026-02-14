"""Policy check router."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from eightton.entity.policy_check import CheckMode, PolicyViolation
from eightton.repository.policy_check_repository import PolicyCheckRepository
from eightton.service.policy_service import PolicyService
from eightton.util.database import get_database

router = APIRouter(prefix="/policy", tags=["policy"])


# ============================================================================
# Standalone DI (no dependency on backend's dependencies.py)
# ============================================================================


def get_policy_check_repository() -> PolicyCheckRepository:
    db = get_database()
    return PolicyCheckRepository(db["policy_checks"])


def get_policy_service(
    repo: Annotated[PolicyCheckRepository, Depends(get_policy_check_repository)],
) -> PolicyService:
    return PolicyService(repo)


PolicyServiceDep = Annotated[PolicyService, Depends(get_policy_service)]


# ============================================================================
# Request/Response Models
# ============================================================================


class ChangedFileInput(BaseModel):
    """Input for a changed file."""

    file_path: str
    content: str | None = None
    change_type: str = "modified"


class PolicyCheckRequest(BaseModel):
    """Policy check request."""

    policy_file: str = Field(..., description="Policy file name (e.g. 'eightton-backend')")
    changed_files: list[ChangedFileInput] = Field(..., description="List of changed files")
    mode: str = Field(default="diff", description="Check mode: diff or full")
    session_id: str | None = None
    github_repo: str | None = None
    branch: str | None = None


class ViolationResponse(BaseModel):
    """Violation in response."""

    rule_id: str
    rule_type: str
    severity: str
    description: str
    file_path: str
    line_number: int | None = None
    matched_pattern: str | None = None
    suggestion: str | None = None


class PolicyCheckResponse(BaseModel):
    """Policy check result response."""

    id: str
    policy_file: str
    check_mode: str
    status: str
    total_rules_checked: int
    violations: list[ViolationResponse]
    files_checked: list[str]
    error_count: int
    warning_count: int
    session_id: str | None = None
    github_repo: str | None = None
    branch: str | None = None
    checked_by: str | None = None
    created_at: str


class GateResponse(BaseModel):
    """Gate check response."""

    allowed: bool
    status: str | None = None
    error_count: int = 0
    warning_count: int = 0
    check_id: str | None = None
    reason: str


class PolicyFileResponse(BaseModel):
    """Policy file info."""

    file: str
    name: str
    version: str
    description: str


class PolicyRuleResponse(BaseModel):
    """Policy rule info."""

    id: str
    type: str
    severity: str
    description: str


# ============================================================================
# Helpers
# ============================================================================


def _violation_to_response(v: PolicyViolation) -> ViolationResponse:
    return ViolationResponse(
        rule_id=v.rule_id,
        rule_type=v.rule_type.value,
        severity=v.severity.value,
        description=v.description,
        file_path=v.file_path,
        line_number=v.line_number,
        matched_pattern=v.matched_pattern,
        suggestion=v.suggestion,
    )


# ============================================================================
# Endpoints
# ============================================================================


@router.get("/files", response_model=list[PolicyFileResponse])
async def list_policy_files(policy_service: PolicyServiceDep):
    """List available policy files."""
    files = policy_service.list_policy_files()
    return [PolicyFileResponse(**f) for f in files]


@router.get("/rules", response_model=list[PolicyRuleResponse])
async def get_policy_rules(
    policy_service: PolicyServiceDep,
    policy_file: str = "eightton-backend",
):
    """Get rules from a specific policy file."""
    try:
        rules = policy_service.get_rules(policy_file)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    return [
        PolicyRuleResponse(
            id=r["id"],
            type=r["type"],
            severity=r.get("severity", "error"),
            description=r.get("description", ""),
        )
        for r in rules
    ]


@router.post("/check", response_model=PolicyCheckResponse)
async def run_policy_check(
    request: PolicyCheckRequest,
    policy_service: PolicyServiceDep,
):
    """Run policy check against changed files."""
    from eightton.service.policy_service import ChangedFile

    try:
        mode = CheckMode(request.mode)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid mode: {request.mode}. Must be 'diff' or 'full'.",
        )

    changed = [
        ChangedFile(
            file_path=f.file_path,
            content=f.content,
            change_type=f.change_type,
        )
        for f in request.changed_files
    ]

    try:
        result = await policy_service.run_check(
            policy_file=request.policy_file,
            changed_files=changed,
            mode=mode,
            session_id=request.session_id,
            github_repo=request.github_repo,
            branch=request.branch,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return PolicyCheckResponse(
        id=str(result.id),
        policy_file=result.policy_file,
        check_mode=result.check_mode.value,
        status=result.status.value,
        total_rules_checked=result.total_rules_checked,
        violations=[_violation_to_response(v) for v in result.violations],
        files_checked=result.files_checked,
        error_count=result.error_count,
        warning_count=result.warning_count,
        session_id=result.session_id,
        github_repo=result.github_repo,
        branch=result.branch,
        checked_by=result.checked_by,
        created_at=result.created_at.isoformat(),
    )


@router.get("/results/{check_id}", response_model=PolicyCheckResponse)
async def get_check_result(
    check_id: str,
    policy_service: PolicyServiceDep,
):
    """Get a specific policy check result."""
    result = await policy_service.get_result(check_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy check result not found",
        )
    return PolicyCheckResponse(
        id=str(result.id),
        policy_file=result.policy_file,
        check_mode=result.check_mode.value,
        status=result.status.value,
        total_rules_checked=result.total_rules_checked,
        violations=[_violation_to_response(v) for v in result.violations],
        files_checked=result.files_checked,
        error_count=result.error_count,
        warning_count=result.warning_count,
        session_id=result.session_id,
        github_repo=result.github_repo,
        branch=result.branch,
        checked_by=result.checked_by,
        created_at=result.created_at.isoformat(),
    )


@router.get("/gate", response_model=GateResponse)
async def policy_gate(
    policy_service: PolicyServiceDep,
    session_id: str | None = None,
    github_repo: str | None = None,
    branch: str | None = None,
):
    """Check if tests are allowed to run based on latest policy check."""
    if not session_id and not (github_repo and branch):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provide session_id or both github_repo and branch.",
        )

    gate = await policy_service.is_policy_passed(
        session_id=session_id,
        github_repo=github_repo,
        branch=branch,
    )
    return GateResponse(**gate)
