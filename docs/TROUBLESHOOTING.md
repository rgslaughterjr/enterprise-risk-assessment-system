# TROUBLESHOOTING GUIDE

Enterprise Risk Assessment System - Production Operations

This guide provides solutions to common issues encountered in production environments. For monitoring and metrics, see [MONITORING.md](MONITORING.md).

## Table of Contents

- [Quick Diagnostics](#quick-diagnostics)
- [Common Errors](#common-errors)
- [API Rate Limit Issues](#api-rate-limit-issues)
- [Memory and Performance Issues](#memory-and-performance-issues)
- [AWS Deployment Failures](#aws-deployment-failures)
- [Debug Logging Setup](#debug-logging-setup)
- [Health Check Procedures](#health-check-procedures)

---

## Quick Diagnostics

### System Health Check

Run this command to quickly verify system health:

```bash
# Check all critical dependencies
python check_tools.py

# Verify API connectivity
python -c "
from src.tools.nvd_client import NVDClient
from src.tools.servicenow_client import ServiceNowClient

print('Testing NVD API...')
nvd = NVDClient()
print('✓ NVD client initialized')

print('Testing ServiceNow API...')
snow = ServiceNowClient()
print('✓ ServiceNow client initialized')
print('All APIs accessible')
"

# Run smoke tests
pytest tests/test_servicenow_client.py::test_get_incidents_basic -v
```

### Environment Validation

```bash
# Check required environment variables
python -c "
import os
required = [
    'ANTHROPIC_API_KEY',
    'SERVICENOW_INSTANCE',
    'SERVICENOW_USERNAME',
    'SERVICENOW_PASSWORD',
    'NVD_API_KEY',
    'VIRUSTOTAL_API_KEY',
    'ALIENVAULT_OTX_KEY'
]
missing = [var for var in required if not os.getenv(var)]
if missing:
    print(f'❌ Missing: {missing}')
    exit(1)
else:
    print('✓ All required environment variables set')
"
```

---

## Common Errors

### 1. ChromaDB Collection Already Exists

**Error:**
```
chromadb.errors.DuplicateCollectionError: Collection 'risk_documents' already exists
```

**Solution:**
```python
# Option 1: Delete existing collection
import chromadb
client = chromadb.Client()
try:
    client.delete_collection("risk_documents")
    print("Collection deleted")
except:
    pass

# Option 2: Use get_or_create_collection
collection = client.get_or_create_collection("risk_documents")
```

**Prevention:**
```python
# In src/tools/hybrid_retriever.py
def __init__(self):
    self.client = chromadb.Client()
    # Always use get_or_create to avoid duplicates
    self.collection = self.client.get_or_create_collection(
        name="risk_documents",
        metadata={"hnsw:space": "cosine"}
    )
```

### 2. ServiceNow Authentication Failures

**Error:**
```
requests.exceptions.HTTPError: 401 Client Error: Unauthorized
```

**Diagnosis:**
```bash
# Test credentials directly
curl -u "admin:password" \
  "https://dev12345.service-now.com/api/now/table/incident?sysparm_limit=1"
```

**Solutions:**

**A. Invalid Credentials:**
```bash
# Verify credentials in .env
grep SERVICENOW .env

# Reset ServiceNow PDI password
# 1. Visit developer.servicenow.com
# 2. Click "Manage" → "Reset Password"
# 3. Update .env file
```

**B. Instance Hibernation:**
```bash
# Wake up hibernated PDI instance
# 1. Visit developer.servicenow.com
# 2. Click "Manage" → "Wake Instance"
# 3. Wait 2-3 minutes
# 4. Retry connection
```

**C. Session Timeout:**
```python
# Add session management to ServiceNowClient
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

session = requests.Session()
retry = Retry(total=3, backoff_factor=1)
adapter = HTTPAdapter(max_retries=retry)
session.mount('https://', adapter)
```

### 3. CVSS Score Parsing Errors

**Error:**
```
ValueError: CVSS score 'N/A' cannot be converted to float
```

**Solution:**
```python
# In src/models/schemas.py
from pydantic import field_validator

class CVEDetail(BaseModel):
    cvss_score: Optional[float] = None

    @field_validator('cvss_score', mode='before')
    def parse_cvss(cls, v):
        if v in [None, 'N/A', '', 'Unknown']:
            return None
        try:
            score = float(v)
            return max(0.0, min(10.0, score))  # Clamp to [0, 10]
        except (ValueError, TypeError):
            return None
```

### 4. LangGraph State Serialization Errors

**Error:**
```
TypeError: Object of type datetime is not JSON serializable
```

**Solution:**
```python
# In src/supervisor/supervisor.py
import json
from datetime import datetime

def serialize_state(state: dict) -> dict:
    """Convert state to JSON-serializable format."""
    def serialize_value(v):
        if isinstance(v, datetime):
            return v.isoformat()
        elif hasattr(v, 'model_dump'):  # Pydantic model
            return v.model_dump()
        elif isinstance(v, (list, tuple)):
            return [serialize_value(x) for x in v]
        elif isinstance(v, dict):
            return {k: serialize_value(val) for k, val in v.items()}
        return v

    return {k: serialize_value(v) for k, v in state.items()}
```

### 5. Document Parser Encoding Issues

**Error:**
```
UnicodeDecodeError: 'utf-8' codec can't decode byte 0x89 in position 0
```

**Solution:**
```python
# In src/tools/document_parser.py
def read_file_safely(file_path: str) -> str:
    """Read file with multiple encoding attempts."""
    encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']

    for encoding in encodings:
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                return f.read()
        except UnicodeDecodeError:
            continue

    # Fallback: read as binary and replace errors
    with open(file_path, 'rb') as f:
        return f.read().decode('utf-8', errors='replace')
```

---

## API Rate Limit Issues

### NVD API Rate Limits

**Limits:**
- With API key: 50 requests / 30 seconds
- Without key: 5 requests / 30 seconds

**Detection:**
```python
# src/tools/nvd_client.py logs rate limit errors
2024-11-18 10:15:32 - ERROR - NVD rate limit exceeded: 403 Forbidden
```

**Solutions:**

**1. Implement Request Throttling:**
```python
from tenacity import retry, wait_exponential, stop_after_attempt
import time

class NVDClient:
    def __init__(self):
        self.last_request_time = 0
        self.min_interval = 0.6  # 50 req/30s = ~1.67 req/s

    def _throttle(self):
        """Ensure minimum interval between requests."""
        now = time.time()
        elapsed = now - self.last_request_time
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self.last_request_time = time.time()

    @retry(wait=wait_exponential(min=2, max=60), stop=stop_after_attempt(5))
    def get_cve(self, cve_id: str):
        self._throttle()
        # ... existing implementation
```

**2. Batch Processing with Delays:**
```python
def analyze_cves_batch(cve_ids: List[str], batch_size: int = 10):
    """Process CVEs in batches to respect rate limits."""
    results = []
    for i in range(0, len(cve_ids), batch_size):
        batch = cve_ids[i:i + batch_size]
        batch_results = [nvd_client.get_cve(cve) for cve in batch]
        results.extend(batch_results)

        # Wait 30 seconds between batches
        if i + batch_size < len(cve_ids):
            time.sleep(30)

    return results
```

**3. Implement Caching:**
```python
from functools import lru_cache
import hashlib
import pickle
from pathlib import Path

class NVDClient:
    def __init__(self, cache_dir: str = ".cache/nvd"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def get_cve(self, cve_id: str):
        # Check cache first
        cache_file = self.cache_dir / f"{cve_id}.pkl"
        if cache_file.exists():
            cache_age = time.time() - cache_file.stat().st_mtime
            if cache_age < 86400:  # 24 hours
                with open(cache_file, 'rb') as f:
                    return pickle.load(f)

        # Fetch from API
        result = self._fetch_from_api(cve_id)

        # Cache result
        with open(cache_file, 'wb') as f:
            pickle.dump(result, f)

        return result
```

### VirusTotal API Rate Limits

**Limits:**
- Free tier: 4 requests / minute
- Premium: 1000 requests / day

**Solution:**
```python
class VirusTotalClient:
    def __init__(self):
        self.request_times = []
        self.max_requests_per_minute = 4

    def _wait_for_rate_limit(self):
        """Ensure we don't exceed 4 req/min."""
        now = time.time()
        # Remove requests older than 60 seconds
        self.request_times = [t for t in self.request_times if now - t < 60]

        if len(self.request_times) >= self.max_requests_per_minute:
            # Wait until oldest request is 60 seconds old
            wait_time = 60 - (now - self.request_times[0])
            if wait_time > 0:
                print(f"Rate limit: waiting {wait_time:.1f}s")
                time.sleep(wait_time)
                self.request_times.pop(0)

        self.request_times.append(time.time())
```

---

## Memory and Performance Issues

### High Memory Usage (>2GB)

**Symptoms:**
```bash
# Monitor memory usage
watch -n 1 'ps aux | grep python | grep -v grep'

# Output shows high RSS (resident set size)
USER  PID  %CPU  %MEM    VSZ   RSS  COMMAND
root  1234  98.5  45.2  4.2GB 3.8GB python demo_full.py
```

**Diagnosis:**
```python
import tracemalloc
import gc

# In demo_full.py or supervisor
tracemalloc.start()

# ... run your code ...

current, peak = tracemalloc.get_traced_memory()
print(f"Current memory: {current / 1024**2:.1f} MB")
print(f"Peak memory: {peak / 1024**2:.1f} MB")

# Get top memory consumers
snapshot = tracemalloc.take_snapshot()
top_stats = snapshot.statistics('lineno')
for stat in top_stats[:10]:
    print(stat)
```

**Solutions:**

**1. Clear ChromaDB Collections After Use:**
```python
def cleanup_vector_store():
    """Free memory from ChromaDB."""
    import gc
    import chromadb

    # Clear collections
    client = chromadb.Client()
    for collection in client.list_collections():
        client.delete_collection(collection.name)

    # Force garbage collection
    gc.collect()
```

**2. Stream Large Document Processing:**
```python
def process_large_pdf_streaming(file_path: str, chunk_size: int = 1000):
    """Process large PDFs in chunks to reduce memory."""
    import PyPDF2

    with open(file_path, 'rb') as f:
        reader = PyPDF2.PdfReader(f)
        total_pages = len(reader.pages)

        for i in range(0, total_pages, chunk_size):
            # Process chunk of pages
            chunk_text = ""
            for page_num in range(i, min(i + chunk_size, total_pages)):
                chunk_text += reader.pages[page_num].extract_text()

            # Process chunk and clear memory
            yield process_chunk(chunk_text)
            chunk_text = None
            gc.collect()
```

**3. Limit Vector Store Size:**
```python
# In src/tools/hybrid_retriever.py
MAX_DOCUMENTS = 10000

def add_documents(self, documents: List[str]):
    """Add documents with size limit."""
    if len(documents) > MAX_DOCUMENTS:
        # Keep only most recent documents
        documents = documents[-MAX_DOCUMENTS:]

    # Add to ChromaDB
    self.collection.add(
        documents=documents,
        ids=[f"doc_{i}" for i in range(len(documents))]
    )
```

### Slow Performance (<10 CVEs/minute)

**Expected Performance:**
- Target: 50+ CVEs/minute
- Acceptable: 20+ CVEs/minute
- Poor: <10 CVEs/minute

**Diagnosis:**
```python
import time
from functools import wraps

def timing_decorator(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        elapsed = time.time() - start
        print(f"{func.__name__}: {elapsed:.2f}s")
        return result
    return wrapper

# Apply to agent methods
@timing_decorator
def analyze_cve(self, cve_id: str):
    # ... implementation
```

**Solutions:**

**1. Parallel API Calls:**
```python
from concurrent.futures import ThreadPoolExecutor, as_completed

def analyze_cves_parallel(cve_ids: List[str], max_workers: int = 5):
    """Analyze multiple CVEs in parallel."""
    results = {}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_cve = {
            executor.submit(analyze_single_cve, cve_id): cve_id
            for cve_id in cve_ids
        }

        # Collect results as they complete
        for future in as_completed(future_to_cve):
            cve_id = future_to_cve[future]
            try:
                results[cve_id] = future.result(timeout=30)
            except Exception as e:
                print(f"Error analyzing {cve_id}: {e}")
                results[cve_id] = None

    return results
```

**2. Optimize Embeddings:**
```python
# Use smaller, faster models for non-critical use cases
from sentence_transformers import SentenceTransformer

# Instead of: all-MiniLM-L12-v2 (384 dim, slower)
# Use: all-MiniLM-L6-v2 (384 dim, 2x faster)
model = SentenceTransformer('all-MiniLM-L6-v2')

# Or use batch encoding
texts = ["text1", "text2", ...]
embeddings = model.encode(texts, batch_size=32, show_progress_bar=True)
```

---

## AWS Deployment Failures

### Lambda Timeout Errors

**Error:**
```
Task timed out after 30.00 seconds
```

**Solutions:**

**1. Increase Lambda Timeout:**
```yaml
# infrastructure/cloudformation/lambda.yml
Resources:
  RiskAssessmentFunction:
    Type: AWS::Lambda::Function
    Properties:
      Timeout: 300  # Increase to 5 minutes
      MemorySize: 3008  # More memory = faster CPU
```

**2. Implement Async Processing:**
```python
# Use Step Functions for long-running workflows
import boto3

def lambda_handler(event, context):
    """Start Step Functions execution for long tasks."""
    sfn = boto3.client('stepfunctions')

    response = sfn.start_execution(
        stateMachineArn=os.environ['STATE_MACHINE_ARN'],
        input=json.dumps(event)
    )

    return {
        'statusCode': 202,
        'body': json.dumps({
            'executionArn': response['executionArn'],
            'message': 'Assessment started'
        })
    }
```

### Bedrock Model Access Denied

**Error:**
```
botocore.exceptions.ClientError: An error occurred (AccessDeniedException) when calling the InvokeModel operation
```

**Solution:**
```bash
# 1. Request model access in AWS Console
# Bedrock → Model access → Manage model access → Select Claude models

# 2. Update IAM role policy
aws iam put-role-policy \
  --role-name lambda-execution-role \
  --policy-name BedrockAccess \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream"
      ],
      "Resource": "arn:aws:bedrock:*::foundation-model/anthropic.claude-*"
    }]
  }'

# 3. Verify access
aws bedrock list-foundation-models --region us-east-1
```

### Docker Build Failures

**Error:**
```
ERROR: failed to solve: process "/bin/sh -c pip install -r requirements.txt" did not complete successfully
```

**Solutions:**

**1. Use Multi-Stage Builds:**
```dockerfile
# docker/Dockerfile
FROM public.ecr.aws/lambda/python:3.11 as builder

# Install build dependencies
RUN yum install -y gcc g++ make

# Install Python dependencies
COPY requirements.txt .
RUN pip install --target /app -r requirements.txt

# Final stage - smaller image
FROM public.ecr.aws/lambda/python:3.11
COPY --from=builder /app /var/task
COPY src/ /var/task/src/
CMD ["src.lambda_handler.handler"]
```

**2. Pin Dependency Versions:**
```txt
# requirements-lambda.txt - frozen versions for reproducibility
langchain==1.0.5
langgraph==1.0.3
chromadb==1.3.4
# ... rest pinned to specific versions
```

---

## Debug Logging Setup

### Enable Detailed Logging

**1. Configure Logging in Application:**
```python
# src/utils/logging_config.py
import logging
import sys
from pathlib import Path

def setup_logging(level: str = "INFO", log_file: str = None):
    """Configure application-wide logging."""
    log_level = getattr(logging, level.upper())

    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    # File handler (optional)
    handlers = [console_handler]
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        handlers.append(file_handler)

    # Configure root logger
    logging.basicConfig(
        level=log_level,
        handlers=handlers,
        force=True
    )

    # Reduce noise from third-party libraries
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('chromadb').setLevel(logging.WARNING)
    logging.getLogger('httpx').setLevel(logging.WARNING)

    return logging.getLogger(__name__)
```

**2. Use in Application:**
```python
# demo_full.py
from src.utils.logging_config import setup_logging

# Debug mode
logger = setup_logging(level="DEBUG", log_file="logs/assessment.log")

# Production mode
logger = setup_logging(level="INFO")
```

**3. Add Structured Logging:**
```python
import json

class StructuredLogger:
    """JSON-formatted logs for CloudWatch insights."""

    def __init__(self, name: str):
        self.logger = logging.getLogger(name)

    def log(self, level: str, message: str, **kwargs):
        """Log with structured metadata."""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": level,
            "message": message,
            **kwargs
        }
        self.logger.log(
            getattr(logging, level.upper()),
            json.dumps(log_entry)
        )

    def info(self, message: str, **kwargs):
        self.log("INFO", message, **kwargs)

    def error(self, message: str, **kwargs):
        self.log("ERROR", message, **kwargs)

# Usage
logger = StructuredLogger("supervisor")
logger.info("Assessment started", cve_count=10, user="admin")
```

### LangSmith Tracing

```bash
# Enable LangSmith for detailed agent traces
export LANGSMITH_TRACING=true
export LANGSMITH_API_KEY="lsv2_pt_..."
export LANGSMITH_PROJECT="enterprise-risk-prod"

# Run with tracing
python demo_full.py

# View traces at: https://smith.langchain.com
```

---

## Health Check Procedures

### Pre-Deployment Health Check

```bash
#!/bin/bash
# scripts/health_check.sh

echo "Running health checks..."

# 1. Environment variables
echo "Checking environment..."
python -c "
import os
required = ['ANTHROPIC_API_KEY', 'SERVICENOW_INSTANCE']
missing = [v for v in required if not os.getenv(v)]
assert not missing, f'Missing: {missing}'
"

# 2. Dependencies
echo "Checking dependencies..."
pip check

# 3. API connectivity
echo "Testing APIs..."
pytest tests/test_servicenow_client.py::test_get_incidents_basic -v

# 4. Vector store
echo "Testing ChromaDB..."
python -c "
import chromadb
client = chromadb.Client()
col = client.get_or_create_collection('health_check')
col.add(documents=['test'], ids=['1'])
assert col.count() == 1
client.delete_collection('health_check')
"

# 5. Model access
echo "Testing Claude API..."
python -c "
from anthropic import Anthropic
client = Anthropic()
response = client.messages.create(
    model='claude-sonnet-4-5-20250929',
    max_tokens=10,
    messages=[{'role': 'user', 'content': 'Hi'}]
)
assert response.content[0].text
"

echo "✓ All health checks passed"
```

### Production Monitoring Script

```python
# scripts/monitor_health.py
import requests
import time
from datetime import datetime

def check_endpoint_health(url: str, timeout: int = 10) -> dict:
    """Check if endpoint is responsive."""
    try:
        start = time.time()
        response = requests.get(url, timeout=timeout)
        latency = (time.time() - start) * 1000

        return {
            "status": "healthy" if response.status_code == 200 else "unhealthy",
            "status_code": response.status_code,
            "latency_ms": latency,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }

if __name__ == "__main__":
    # Check API Gateway endpoint
    result = check_endpoint_health("https://api.example.com/health")
    print(json.dumps(result, indent=2))
```

---

## Getting Help

If you encounter issues not covered here:

1. **Check Logs:**
   ```bash
   tail -f logs/assessment.log
   ```

2. **Enable Debug Mode:**
   ```python
   setup_logging(level="DEBUG")
   ```

3. **Review LangSmith Traces:**
   - Visit https://smith.langchain.com
   - Filter by project: `enterprise-risk-prod`
   - Examine failed runs

4. **Run Diagnostics:**
   ```bash
   python check_tools.py
   pytest -v --tb=short
   ```

5. **Contact Support:**
   - GitHub Issues: [repo]/issues
   - Email: ops-team@example.com
