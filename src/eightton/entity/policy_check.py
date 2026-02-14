"""Policy check entity models."""

from enum import Enum

from pydantic import BaseModel, Field

from eightton.entity.base import BaseEntity


class PolicySeverity(str, Enum):
    """Policy rule severity."""

    ERROR = "error"
    WARNING = "warning"


class PolicyRuleType(str, Enum):
    """Policy rule type."""

    PROTECTED_PATH = "protected_path"
    LAYER_RULE = "layer_rule"
    CODE_CONVENTION = "code_convention"


class CheckMode(str, Enum):
    """Policy check mode."""

    DIFF = "diff"
    FULL = "full"


class CheckStatus(str, Enum):
    """Policy check result status."""

    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"


class PolicyViolation(BaseModel):
    """A single policy violation."""

    rule_id: str = Field(..., description="Policy rule ID")
    rule_type: PolicyRuleType = Field(..., description="Type of policy rule")
    severity: PolicySeverity = Field(..., description="Violation severity")
    description: str = Field(..., description="Rule description")
    file_path: str = Field(..., description="File where violation occurred")
    line_number: int | None = Field(default=None, description="Line number of violation")
    matched_pattern: str | None = Field(default=None, description="Pattern that matched")
    suggestion: str | None = Field(default=None, description="Suggestion to fix")


class PolicyCheckResult(BaseEntity):
    """Policy check result entity."""

    session_id: str | None = Field(default=None, description="Related work session ID")
    github_repo: str | None = Field(default=None, description="GitHub repository (owner/repo)")
    branch: str | None = Field(default=None, description="Branch name")
    policy_file: str = Field(..., description="Policy file used for check")
    check_mode: CheckMode = Field(default=CheckMode.DIFF, description="Check mode")
    status: CheckStatus = Field(default=CheckStatus.PASSED, description="Overall check status")
    total_rules_checked: int = Field(default=0, description="Total rules evaluated")
    violations: list[PolicyViolation] = Field(
        default_factory=list, description="List of violations"
    )
    files_checked: list[str] = Field(default_factory=list, description="Files that were checked")
    error_count: int = Field(default=0, description="Number of error-level violations")
    warning_count: int = Field(default=0, description="Number of warning-level violations")
    checked_by: str | None = Field(default=None, description="User who triggered check")
