# LLM Portal Dockerfile
# Build: docker build -t llm-portal .
# Run:   docker run -p 8081:8081 -v ./config.toml:/app/config.toml -v ./data:/app/data llm-portal

FROM python:3.12-slim

WORKDIR /app

# Copy application code
COPY llm_portal/ ./llm_portal/
COPY config.example.toml ./
COPY userctl.sh ./
COPY scripts/ ./scripts/

# Create data and log directories
RUN mkdir -p data logs && \
    chmod +x userctl.sh scripts/*.sh

# Default port
EXPOSE 8081

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8081/portal/login')" || exit 1

# Run portal by default; override with "python3 -m llm_portal proxy" for proxy
CMD ["python3", "-m", "llm_portal"]
