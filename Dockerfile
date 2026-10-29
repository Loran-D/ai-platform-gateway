FROM python:3.10-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src/ ./src/


RUN pip install --no-cache-dir .

CMD ["python3", "-m", "ai_platform_gateway.mcp_server"]