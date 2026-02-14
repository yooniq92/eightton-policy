"""Base entity model."""

from datetime import datetime, timezone
from typing import Annotated, Any

from bson import ObjectId
from pydantic import BaseModel, Field, field_validator


class PyObjectId(ObjectId):
    """Custom ObjectId type for Pydantic v2."""

    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v: Any, handler: Any = None) -> ObjectId:
        """Validate ObjectId - compatible with Pydantic v2."""
        if isinstance(v, ObjectId):
            return v
        if isinstance(v, str):
            if ObjectId.is_valid(v):
                return ObjectId(v)
        raise ValueError("Invalid ObjectId")

    @classmethod
    def __get_pydantic_json_schema__(cls, _field_schema: Any) -> dict[str, Any]:
        return {"type": "string"}


def utc_now() -> datetime:
    """Return current UTC time."""
    return datetime.now(timezone.utc)


class BaseEntity(BaseModel):
    """Base entity with common fields."""

    id: Annotated[PyObjectId | None, Field(alias="_id", default=None)]
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    model_config = {
        "populate_by_name": True,
        "arbitrary_types_allowed": True,
        "json_encoders": {ObjectId: str, datetime: lambda v: v.isoformat()},
    }

    @field_validator("id", mode="before")
    @classmethod
    def validate_object_id(cls, v: Any) -> PyObjectId | None:
        if v is None:
            return None
        if isinstance(v, ObjectId):
            return PyObjectId(v)
        if isinstance(v, str) and ObjectId.is_valid(v):
            return PyObjectId(v)
        return None

    def model_dump_for_db(self) -> dict[str, Any]:
        """Dump model for MongoDB insert/update."""
        data = self.model_dump(by_alias=True, exclude_none=True)
        if "_id" in data and data["_id"] is None:
            del data["_id"]
        return data
