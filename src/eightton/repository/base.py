"""Base repository with common CRUD operations."""

from typing import Any, Generic, TypeVar

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorCollection
from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


class BaseRepository(Generic[T]):
    """Base repository with common CRUD operations."""

    def __init__(self, collection: AsyncIOMotorCollection, model_class: type[T]):
        self._collection = collection
        self._model_class = model_class

    @property
    def collection(self) -> AsyncIOMotorCollection:
        """Get the MongoDB collection."""
        return self._collection

    async def insert(self, entity: T) -> T:
        """Insert a new entity."""
        data = entity.model_dump(by_alias=True, exclude_none=True)
        if "_id" in data and data["_id"] is None:
            del data["_id"]
        result = await self._collection.insert_one(data)
        # Reload to get the inserted document with _id
        inserted = await self._collection.find_one({"_id": result.inserted_id})
        return self._model_class.model_validate(inserted)

    async def find_by_id(self, entity_id: str | ObjectId) -> T | None:
        """Find entity by ID."""
        if isinstance(entity_id, str):
            if not ObjectId.is_valid(entity_id):
                return None
            entity_id = ObjectId(entity_id)
        doc = await self._collection.find_one({"_id": entity_id})
        if doc:
            return self._model_class.model_validate(doc)
        return None

    async def find_one(self, query: dict[str, Any]) -> T | None:
        """Find one entity by query."""
        doc = await self._collection.find_one(query)
        if doc:
            return self._model_class.model_validate(doc)
        return None

    async def find_many(
        self,
        query: dict[str, Any] | None = None,
        skip: int = 0,
        limit: int = 100,
        sort: list[tuple[str, int]] | None = None,
    ) -> list[T]:
        """Find multiple entities."""
        cursor = self._collection.find(query or {})
        if sort:
            cursor = cursor.sort(sort)
        cursor = cursor.skip(skip).limit(limit)
        docs = await cursor.to_list(length=limit)
        return [self._model_class.model_validate(doc) for doc in docs]

    async def update(self, entity_id: str | ObjectId, update_data: dict[str, Any]) -> T | None:
        """Update an entity."""
        if isinstance(entity_id, str):
            entity_id = ObjectId(entity_id)
        result = await self._collection.find_one_and_update(
            {"_id": entity_id},
            {"$set": update_data},
            return_document=True,
        )
        if result:
            return self._model_class.model_validate(result)
        return None

    async def delete(self, entity_id: str | ObjectId) -> bool:
        """Delete an entity."""
        if isinstance(entity_id, str):
            entity_id = ObjectId(entity_id)
        result = await self._collection.delete_one({"_id": entity_id})
        return result.deleted_count > 0

    async def count(self, query: dict[str, Any] | None = None) -> int:
        """Count entities."""
        return await self._collection.count_documents(query or {})

    async def exists(self, query: dict[str, Any]) -> bool:
        """Check if entity exists."""
        count = await self._collection.count_documents(query, limit=1)
        return count > 0
