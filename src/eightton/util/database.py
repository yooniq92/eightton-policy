"""Database connection management."""

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from eightton.config import settings

_client: AsyncIOMotorClient | None = None
_database: AsyncIOMotorDatabase | None = None


async def connect_to_mongodb() -> AsyncIOMotorDatabase:
    """Connect to MongoDB and return the database instance."""
    global _client, _database
    
    if _client is None:
        _client = AsyncIOMotorClient(settings.mongodb_uri)
        _database = _client[settings.mongodb_database]
    
    return _database


async def close_mongodb_connection():
    """Close MongoDB connection."""
    global _client, _database
    
    if _client is not None:
        _client.close()
        _client = None
        _database = None


def get_database() -> AsyncIOMotorDatabase:
    """Get the database instance."""
    if _database is None:
        raise RuntimeError("Database not connected. Call connect_to_mongodb() first.")
    return _database
