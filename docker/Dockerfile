# Multi-stage Dockerfile for Enterprise Risk Assessment System
# Target: <500MB final image with python:3.11-slim

# =============================================================================
# STAGE 1: Builder - Install dependencies and compile wheels
# =============================================================================
FROM python:3.11-slim AS builder

# Set working directory
WORKDIR /build

# Install system dependencies for building Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    make \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements files
COPY requirements.txt ./
# COPY requirements-dev.txt ./

# Create virtual environment
RUN python -m venv /opt/venv

# Enable venv
ENV PATH="/opt/venv/bin:$PATH"

# Upgrade pip and install wheel
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Install production dependencies only
RUN pip install --no-cache-dir -r requirements.txt

# =============================================================================
# STAGE 2: Runtime - Minimal production image
# =============================================================================
FROM python:3.11-slim AS runtime

# Set labels
LABEL maintainer="Enterprise Risk Assessment Team"
LABEL version="1.0.0"
LABEL description="AWS Bedrock-powered Risk Assessment System"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Set working directory
WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Enable venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code
COPY src/ ./src/
# COPY config/ ./config/
COPY data/ ./data/

# Create necessary directories
RUN mkdir -p /app/logs /app/temp /app/cache && \
    chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Expose port (configurable via ENV)
EXPOSE 8080

# Default command - can be overridden
CMD ["python", "-m", "uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8080"]

# =============================================================================
# STAGE 3: Lambda - Optimized for AWS Lambda deployment
# =============================================================================
FROM public.ecr.aws/lambda/python:3.11 AS lambda

# Set working directory
WORKDIR ${LAMBDA_TASK_ROOT}

# Copy application code
COPY src/ ./src/
# COPY config/ ./config/

# Install dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Set Lambda handler
CMD ["src.deployment.lambda_handler.orchestrate_assessment"]

# =============================================================================
# STAGE 4: Development - Includes dev tools and testing dependencies
# =============================================================================
FROM runtime AS development

USER root

# Install development dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Install dev Python packages
# COPY requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements-dev.txt

# Copy test files
COPY tests/ ./tests/
COPY pytest.ini ./
COPY .coveragerc ./

# Switch back to appuser
USER appuser

# Default command for development
CMD ["pytest", "tests/", "-v"]

# =============================================================================
# STAGE 5: Testing - Optimized for CI/CD testing
# =============================================================================
FROM development AS testing

USER root

# Install additional testing tools
RUN pip install --no-cache-dir \
    pytest-xdist \
    pytest-benchmark \
    pytest-timeout

# Copy all test fixtures and data
COPY tests/fixtures/ ./tests/fixtures/

USER appuser

# Run tests with coverage
CMD ["pytest", "tests/", "-v", "--cov=src", "--cov-report=term-missing", "--cov-report=html"]

# =============================================================================
# Image size optimization notes:
# - Builder stage: Compiles dependencies, discarded in final image
# - Runtime stage: Only necessary runtime files (~200-300MB)
# - Lambda stage: Optimized for AWS Lambda (<500MB)
# - Development stage: Adds dev tools for local development
# - Testing stage: Includes full test suite for CI/CD
#
# Build commands:
# - Production: docker build --target runtime -t risk-assessment:latest .
# - Lambda: docker build --target lambda -t risk-assessment:lambda .
# - Development: docker build --target development -t risk-assessment:dev .
# - Testing: docker build --target testing -t risk-assessment:test .
# =============================================================================
