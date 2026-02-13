FROM python:3.12-slim

WORKDIR /app

# Install uv for fast dependency management
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy dependency files first for layer caching
COPY pyproject.toml uv.lock .python-version ./

# Install dependencies (production only)
RUN uv sync --frozen --no-dev --no-install-project

# Copy application code
COPY main.py ./
COPY spanner_agent/ ./spanner_agent/

# Port 8000 matches existing Cloud Run config
ENV PORT=8000

CMD ["uv", "run", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
