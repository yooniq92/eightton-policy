FROM python:3.12-slim

WORKDIR /app

# Copy uv from official image (multi-arch)
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Copy all source files first
COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY policies/ ./policies/

# Create virtual environment and install dependencies
RUN uv venv --clear /app/.venv && \
    . /app/.venv/bin/activate && \
    uv pip install -e . --no-cache

# Expose port
EXPOSE 8000

# Run the policy service
CMD ["/app/.venv/bin/python", "-m", "uvicorn", "eightton.main:app", "--host", "0.0.0.0", "--port", "8000"]
