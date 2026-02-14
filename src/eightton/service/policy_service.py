"""Policy check service."""

import fnmatch
import logging
import re
from pathlib import Path, PurePath
from typing import Any

import yaml
from pydantic import BaseModel, Field

from eightton.entity.policy_check import (
    CheckMode,
    CheckStatus,
    PolicyCheckResult,
    PolicyRuleType,
    PolicySeverity,
    PolicyViolation,
)
from eightton.repository.policy_check_repository import PolicyCheckRepository

logger = logging.getLogger(__name__)

POLICIES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "policies"


def _match_path(file_path: str, pattern: str) -> bool:
    """Match a file path against a glob pattern. Supports ** for recursive matching."""
    if "**" not in pattern:
        return fnmatch.fnmatch(file_path, pattern)
    # Convert glob pattern to regex: ** matches zero or more path segments
    regex = pattern.replace(".", r"\.")
    regex = regex.replace("**/", "(?:.+/)?")
    regex = regex.replace("**", ".*")
    regex = regex.replace("*", "[^/]*")
    return bool(re.fullmatch(regex, file_path))


class ChangedFile(BaseModel):
    """Input representing a changed file."""

    file_path: str = Field(..., description="Relative file path")
    content: str | None = Field(default=None, description="File content (for layer/convention)")
    change_type: str = Field(default="modified", description="added, modified, deleted")


class PolicyService:
    """Service for policy checking."""

    def __init__(self, policy_check_repo: PolicyCheckRepository):
        self._repo = policy_check_repo

    def _load_policies(self, policy_file: str) -> dict[str, Any]:
        """Load policies from a YAML file in the policies directory."""
        if not policy_file.endswith(".yaml"):
            policy_file = f"{policy_file}.yaml"
        path = POLICIES_DIR / policy_file
        if not path.exists():
            raise ValueError(f"Policy file not found: {policy_file}")
        with open(path) as f:
            return yaml.safe_load(f)

    def list_policy_files(self) -> list[dict[str, str]]:
        """List available policy files."""
        if not POLICIES_DIR.exists():
            return []
        files = []
        for p in sorted(POLICIES_DIR.glob("*.yaml")):
            try:
                data = yaml.safe_load(p.read_text())
                files.append({
                    "file": p.stem,
                    "name": data.get("name", p.stem),
                    "version": data.get("version", ""),
                    "description": data.get("description", ""),
                })
            except Exception:
                files.append({"file": p.stem, "name": p.stem, "version": "", "description": ""})
        return files

    def get_rules(self, policy_file: str) -> list[dict[str, Any]]:
        """Get all rules from a specific policy file."""
        data = self._load_policies(policy_file)
        policies = data.get("policies", {})
        rules: list[dict[str, Any]] = []

        for rule in policies.get("protected_paths", []):
            rules.append({
                "id": rule["id"],
                "type": "protected_path",
                "severity": rule.get("severity", "error"),
                "description": rule.get("description", ""),
                "patterns": rule.get("patterns", []),
            })

        for rule in policies.get("layer_rules", []):
            rules.append({
                "id": rule["id"],
                "type": "layer_rule",
                "severity": rule.get("severity", "error"),
                "description": rule.get("description", ""),
                "source_pattern": rule.get("source_pattern", ""),
                "forbidden_imports": rule.get("forbidden_imports", []),
                "exclude": rule.get("exclude", []),
            })

        for rule in policies.get("code_conventions", []):
            rules.append({
                "id": rule["id"],
                "type": "code_convention",
                "severity": rule.get("severity", "warning"),
                "description": rule.get("description", ""),
                "check_type": rule.get("check_type", ""),
                "target_pattern": rule.get("target_pattern", ""),
                "exclude": rule.get("exclude", []),
            })

        return rules

    async def run_check(
        self,
        policy_file: str,
        changed_files: list[ChangedFile],
        mode: CheckMode = CheckMode.DIFF,
        session_id: str | None = None,
        github_repo: str | None = None,
        branch: str | None = None,
        checked_by: str | None = None,
    ) -> PolicyCheckResult:
        """Run policy check against changed files."""
        data = self._load_policies(policy_file)
        policies = data.get("policies", {})

        violations: list[PolicyViolation] = []
        total_rules = 0
        files_checked = list({f.file_path for f in changed_files})

        # Check protected paths
        for rule in policies.get("protected_paths", []):
            total_rules += 1
            violations.extend(self._check_protected_paths(rule, changed_files))

        # Check layer rules
        for rule in policies.get("layer_rules", []):
            total_rules += 1
            violations.extend(self._check_layer_rule(rule, changed_files))

        # Check code conventions
        for rule in policies.get("code_conventions", []):
            total_rules += 1
            violations.extend(self._check_code_convention(rule, changed_files))

        error_count = sum(1 for v in violations if v.severity == PolicySeverity.ERROR)
        warning_count = sum(1 for v in violations if v.severity == PolicySeverity.WARNING)

        if error_count > 0:
            status = CheckStatus.FAILED
        elif warning_count > 0:
            status = CheckStatus.WARNING
        else:
            status = CheckStatus.PASSED

        result = PolicyCheckResult(
            session_id=session_id,
            github_repo=github_repo,
            branch=branch,
            policy_file=policy_file.removesuffix(".yaml"),
            check_mode=mode,
            status=status,
            total_rules_checked=total_rules,
            violations=violations,
            files_checked=files_checked,
            error_count=error_count,
            warning_count=warning_count,
            checked_by=checked_by,
        )

        saved = await self._repo.insert(result)
        return saved

    async def is_policy_passed(
        self,
        session_id: str | None = None,
        github_repo: str | None = None,
        branch: str | None = None,
    ) -> dict[str, Any]:
        """Check if the latest policy check passed (gate check)."""
        result: PolicyCheckResult | None = None

        if session_id:
            result = await self._repo.find_latest_by_session(session_id)
        elif github_repo and branch:
            result = await self._repo.find_latest_by_repo_branch(github_repo, branch)

        if not result:
            return {
                "allowed": False,
                "reason": "No policy check found. Run a policy check first.",
                "check_id": None,
            }

        allowed = result.status != CheckStatus.FAILED
        return {
            "allowed": allowed,
            "status": result.status.value,
            "error_count": result.error_count,
            "warning_count": result.warning_count,
            "check_id": str(result.id),
            "reason": (
                "Policy check passed" if allowed else f"{result.error_count} error(s) found"
            ),
        }

    async def get_result(self, check_id: str) -> PolicyCheckResult | None:
        """Get a policy check result by ID."""
        return await self._repo.find_by_id(check_id)

    # ========================================================================
    # Internal checkers
    # ========================================================================

    def _check_protected_paths(
        self, rule: dict[str, Any], changed_files: list[ChangedFile]
    ) -> list[PolicyViolation]:
        """Check if changed files match protected path patterns."""
        violations: list[PolicyViolation] = []
        patterns = rule.get("patterns", [])
        severity = PolicySeverity(rule.get("severity", "error"))

        for cf in changed_files:
            for pattern in patterns:
                if _match_path(cf.file_path, pattern):
                    violations.append(PolicyViolation(
                        rule_id=rule["id"],
                        rule_type=PolicyRuleType.PROTECTED_PATH,
                        severity=severity,
                        description=rule.get("description", ""),
                        file_path=cf.file_path,
                        matched_pattern=pattern,
                        suggestion=f"File '{cf.file_path}' is protected and should not be modified.",
                    ))
        return violations

    def _check_layer_rule(
        self, rule: dict[str, Any], changed_files: list[ChangedFile]
    ) -> list[PolicyViolation]:
        """Check if files contain forbidden imports based on layer rules."""
        violations: list[PolicyViolation] = []
        source_pattern = rule.get("source_pattern", "")
        forbidden_imports = rule.get("forbidden_imports", [])
        excludes = rule.get("exclude", [])
        severity = PolicySeverity(rule.get("severity", "error"))

        for cf in changed_files:
            if not _match_path(cf.file_path, source_pattern):
                continue
            if any(_match_path(cf.file_path, ex) for ex in excludes):
                continue
            if not cf.content:
                continue

            for line_num, line in enumerate(cf.content.splitlines(), start=1):
                for forbidden in forbidden_imports:
                    if forbidden in line:
                        violations.append(PolicyViolation(
                            rule_id=rule["id"],
                            rule_type=PolicyRuleType.LAYER_RULE,
                            severity=severity,
                            description=rule.get("description", ""),
                            file_path=cf.file_path,
                            line_number=line_num,
                            matched_pattern=forbidden,
                            suggestion=f"Remove forbidden import '{forbidden}' from this layer.",
                        ))
        return violations

    def _check_code_convention(
        self, rule: dict[str, Any], changed_files: list[ChangedFile]
    ) -> list[PolicyViolation]:
        """Check code conventions (class inheritance, pattern presence)."""
        violations: list[PolicyViolation] = []
        check_type = rule.get("check_type", "")
        target_pattern = rule.get("target_pattern", "")
        excludes = rule.get("exclude", [])
        severity = PolicySeverity(rule.get("severity", "warning"))

        for cf in changed_files:
            if not _match_path(cf.file_path, target_pattern):
                continue
            if any(_match_path(cf.file_path, ex) for ex in excludes):
                continue
            if not cf.content:
                continue

            if check_type == "class_inheritance":
                violations.extend(
                    self._check_class_inheritance(rule, cf, severity)
                )
            elif check_type == "pattern_present":
                violations.extend(
                    self._check_pattern_present(rule, cf, severity)
                )

        return violations

    def _check_class_inheritance(
        self,
        rule: dict[str, Any],
        cf: ChangedFile,
        severity: PolicySeverity,
    ) -> list[PolicyViolation]:
        """Check that classes extend a required base class."""
        violations: list[PolicyViolation] = []
        required_base = rule.get("required_base", "")
        # Find class definitions
        class_pattern = re.compile(r"^class\s+(\w+)\s*(\(([^)]*)\))?:", re.MULTILINE)

        for match in class_pattern.finditer(cf.content):
            class_name = match.group(1)
            bases = match.group(3) or ""
            line_num = cf.content[: match.start()].count("\n") + 1

            if required_base not in bases:
                violations.append(PolicyViolation(
                    rule_id=rule["id"],
                    rule_type=PolicyRuleType.CODE_CONVENTION,
                    severity=severity,
                    description=rule.get("description", ""),
                    file_path=cf.file_path,
                    line_number=line_num,
                    matched_pattern=f"class {class_name}",
                    suggestion=f"Class '{class_name}' should extend '{required_base}'.",
                ))
        return violations

    def _check_pattern_present(
        self,
        rule: dict[str, Any],
        cf: ChangedFile,
        severity: PolicySeverity,
    ) -> list[PolicyViolation]:
        """Check that a required pattern is present in the file."""
        violations: list[PolicyViolation] = []
        required_pattern = rule.get("required_pattern", "")

        if not re.search(required_pattern, cf.content):
            violations.append(PolicyViolation(
                rule_id=rule["id"],
                rule_type=PolicyRuleType.CODE_CONVENTION,
                severity=severity,
                description=rule.get("description", ""),
                file_path=cf.file_path,
                matched_pattern=required_pattern,
                suggestion=f"Required pattern '{required_pattern}' not found in file.",
            ))
        return violations
