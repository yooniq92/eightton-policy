"""Policy check repository."""

from motor.motor_asyncio import AsyncIOMotorCollection

from eightton.entity.policy_check import PolicyCheckResult
from eightton.repository.base import BaseRepository


class PolicyCheckRepository(BaseRepository[PolicyCheckResult]):
    """Policy check result repository."""

    def __init__(self, collection: AsyncIOMotorCollection):
        super().__init__(collection, PolicyCheckResult)

    async def find_latest_by_session(self, session_id: str) -> PolicyCheckResult | None:
        """Find the latest policy check result for a session."""
        results = await self.find_many(
            {"session_id": session_id},
            limit=1,
            sort=[("created_at", -1)],
        )
        return results[0] if results else None

    async def find_latest_by_repo_branch(
        self, github_repo: str, branch: str
    ) -> PolicyCheckResult | None:
        """Find the latest policy check result for a repo+branch."""
        results = await self.find_many(
            {"github_repo": github_repo, "branch": branch},
            limit=1,
            sort=[("created_at", -1)],
        )
        return results[0] if results else None
