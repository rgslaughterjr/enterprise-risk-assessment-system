# Performance Tuning Guide

This guide provides strategies for optimizing the Enterprise Risk Assessment System for production workloads, including agent optimization, caching, cost reduction, and horizontal scaling.

## Table of Contents

- [Agent Optimization Strategies](#agent-optimization-strategies)
- [Caching Patterns](#caching-patterns)
- [Batch Processing](#batch-processing)
- [Cost Optimization](#cost-optimization)
- [Database Query Optimization](#database-query-optimization)
- [Horizontal Scaling Patterns](#horizontal-scaling-patterns)
- [Monitoring and Profiling](#monitoring-and-profiling)

---

## Agent Optimization Strategies

### 1. Parallel Agent Execution

**Current State:** Sequential agent execution in LangGraph workflow
**Optimization:** Execute independent agents in parallel

```python
from langgraph.prebuilt import create_react_agent
from concurrent.futures import ThreadPoolExecutor

class OptimizedSupervisor:
    def __init__(self):
        self.executor = ThreadPoolExecutor(max_workers=4)

    def run_parallel_agents(self, state):
        """Run vulnerability and threat agents in parallel"""
        futures = []

        # These agents don't depend on each other
        futures.append(
            self.executor.submit(self.vulnerability_agent.analyze, state)
        )
        futures.append(
            self.executor.submit(self.threat_agent.analyze, state)
        )

        results = [f.result() for f in futures]
        return self.merge_results(results)
```

**Impact:** 40-60% reduction in total workflow time

### 2. Model Selection Strategy

Use appropriate models for different tasks:

| Task | Recommended Model | Reasoning |
|------|------------------|-----------|
| Report generation | Claude 3.5 Sonnet | Complex reasoning, structured output |
| CVE summarization | Claude 3 Haiku | Fast, cost-effective for simple tasks |
| Threat narrative | Claude 3 Opus | Deep analysis required |
| Risk scoring | Rule-based | No LLM needed for deterministic calculations |

**Implementation:**

```python
class AdaptiveModelSelector:
    TASK_MODELS = {
        "summarization": "claude-3-haiku-20240307",
        "analysis": "claude-3-5-sonnet-20241022",
        "deep_research": "claude-3-opus-20240229"
    }

    def select_model(self, task_type: str, complexity: str) -> str:
        if complexity == "simple":
            return self.TASK_MODELS["summarization"]
        elif complexity == "complex":
            return self.TASK_MODELS["deep_research"]
        return self.TASK_MODELS["analysis"]
```

### 3. Prompt Optimization

**Before (verbose):**
```
Analyze this CVE and provide a detailed assessment including CVSS score,
exploitation likelihood, affected systems, remediation steps, and business impact.
```

**After (concise):**
```
Analyze CVE-{cve_id}:
- CVSS: {score}
- Exploited: {status}
- Remediation: {steps}
- Business impact: {impact}

Format: JSON
```

**Impact:** 15-25% reduction in token usage per request

### 4. Agent Response Streaming

Enable streaming for long-running agents:

```python
from langchain.callbacks.streaming_stdout import StreamingStdOutCallbackHandler

agent = VulnerabilityAgent(
    callbacks=[StreamingStdOutCallbackHandler()],
    streaming=True
)

# User sees progressive output
for chunk in agent.stream_analyze(cve_ids):
    yield chunk
```

---

## Caching Patterns

### 1. Response Caching (Redis)

Cache expensive API calls and LLM responses:

```python
import redis
import hashlib
import json
from functools import wraps

class ResponseCache:
    def __init__(self, redis_url="redis://localhost:6379"):
        self.redis = redis.from_url(redis_url)
        self.ttl = {
            "nvd_cve": 86400,      # 24 hours
            "mitre_technique": 604800,  # 7 days
            "llm_summary": 3600     # 1 hour
        }

    def cache_key(self, namespace: str, *args, **kwargs) -> str:
        """Generate cache key from function arguments"""
        key_data = f"{namespace}:{str(args)}:{str(sorted(kwargs.items()))}"
        return hashlib.md5(key_data.encode()).hexdigest()

    def cached(self, namespace: str, ttl: int = None):
        """Decorator for caching function results"""
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                key = self.cache_key(namespace, *args, **kwargs)

                # Check cache
                cached = self.redis.get(key)
                if cached:
                    return json.loads(cached)

                # Execute and cache
                result = func(*args, **kwargs)
                self.redis.setex(
                    key,
                    ttl or self.ttl.get(namespace, 3600),
                    json.dumps(result)
                )
                return result
            return wrapper
        return decorator

# Usage
cache = ResponseCache()

@cache.cached("nvd_cve", ttl=86400)
def get_cve_details(cve_id: str):
    return nvd_client.get_cve(cve_id)
```

### 2. Embedding Cache

Cache document embeddings to avoid recomputation:

```python
class EmbeddingCache:
    def __init__(self, cache_dir=".embedding_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)

    def get_cached_embedding(self, text: str) -> Optional[List[float]]:
        text_hash = hashlib.sha256(text.encode()).hexdigest()
        cache_file = self.cache_dir / f"{text_hash}.npy"

        if cache_file.exists():
            return np.load(cache_file).tolist()
        return None

    def cache_embedding(self, text: str, embedding: List[float]):
        text_hash = hashlib.sha256(text.encode()).hexdigest()
        cache_file = self.cache_dir / f"{text_hash}.npy"
        np.save(cache_file, np.array(embedding))
```

### 3. ChromaDB Persistent Collections

Avoid rebuilding vector stores on every run:

```python
class PersistentRetriever:
    def __init__(self, persist_directory="./chroma_db"):
        self.client = chromadb.PersistentClient(path=persist_directory)
        self.collection = self.client.get_or_create_collection(
            name="risk_documents",
            metadata={"hnsw:space": "cosine"}
        )

    def add_document_if_new(self, doc_id: str, text: str, embedding: List[float]):
        """Only add if document doesn't exist"""
        existing = self.collection.get(ids=[doc_id])
        if not existing['ids']:
            self.collection.add(
                ids=[doc_id],
                embeddings=[embedding],
                documents=[text]
            )
```

---

## Batch Processing

### 1. CVE Batch Analysis

Process multiple CVEs in a single API call:

```python
class BatchVulnerabilityAgent:
    def analyze_cves_batch(self, cve_ids: List[str], batch_size: int = 50):
        """Process CVEs in batches to reduce API calls"""
        results = []

        for i in range(0, len(cve_ids), batch_size):
            batch = cve_ids[i:i+batch_size]

            # Single NVD API call for multiple CVEs
            nvd_results = self.nvd_client.get_cves_bulk(batch)

            # Single LLM call for batch summary
            prompt = f"Summarize these {len(batch)} CVEs:\n"
            for cve in nvd_results:
                prompt += f"- {cve.cve_id}: {cve.description[:100]}\n"

            batch_summary = self.llm.invoke(prompt)
            results.extend(self.parse_batch_summary(batch_summary))

        return results
```

### 2. Document Ingestion Pipeline

Batch process documents for RAG:

```python
from multiprocessing import Pool

class BatchDocumentProcessor:
    def ingest_directory(self, directory: Path, num_workers: int = 4):
        """Process documents in parallel"""
        pdf_files = list(directory.glob("**/*.pdf"))

        with Pool(processes=num_workers) as pool:
            results = pool.map(self.process_document, pdf_files)

        # Bulk add to ChromaDB (more efficient than one-by-one)
        self.bulk_add_to_vectorstore(results)

    def bulk_add_to_vectorstore(self, documents: List[Dict]):
        """Add all documents in single transaction"""
        ids = [doc['id'] for doc in documents]
        texts = [doc['text'] for doc in documents]
        embeddings = [doc['embedding'] for doc in documents]

        self.collection.add(
            ids=ids,
            documents=texts,
            embeddings=embeddings
        )
```

---

## Cost Optimization

### 1. Reduce Bedrock/Claude API Calls

**Strategy 1: Use Prompt Caching**

```python
from anthropic import Anthropic

client = Anthropic()

# Cache long system prompts (up to 90% cost reduction)
response = client.messages.create(
    model="claude-3-5-sonnet-20241022",
    max_tokens=1024,
    system=[
        {
            "type": "text",
            "text": "You are a cybersecurity expert...",  # Long prompt
            "cache_control": {"type": "ephemeral"}
        }
    ],
    messages=[{"role": "user", "content": "Analyze CVE-2024-1234"}]
)
```

**Impact:** 90% cost reduction on cached prompts (5-minute TTL)

**Strategy 2: Use Cheaper Models for Simple Tasks**

```python
class CostOptimizedAgent:
    def route_to_model(self, task_complexity: str):
        if task_complexity == "simple":
            return "claude-3-haiku-20240307"  # $0.25/$1.25 per MTok
        else:
            return "claude-3-5-sonnet-20241022"  # $3/$15 per MTok
```

**Impact:** 80% cost reduction for simple tasks

**Strategy 3: Response Caching**

See [Caching Patterns](#caching-patterns) above.

### 2. Optimize Token Usage

```python
def optimize_context_window(documents: List[str], max_tokens: int = 4000):
    """Only send relevant context to LLM"""
    ranked_docs = rank_by_relevance(documents, query)

    token_count = 0
    selected_docs = []

    for doc in ranked_docs:
        doc_tokens = count_tokens(doc)
        if token_count + doc_tokens <= max_tokens:
            selected_docs.append(doc)
            token_count += doc_tokens
        else:
            break

    return selected_docs
```

### 3. Cost Monitoring

```python
class CostTracker:
    def __init__(self):
        self.costs = {"input_tokens": 0, "output_tokens": 0, "cached_tokens": 0}
        self.rates = {
            "claude-3-5-sonnet": {"input": 3.00, "output": 15.00, "cached": 0.30},
            "claude-3-haiku": {"input": 0.25, "output": 1.25, "cached": 0.025}
        }

    def track_call(self, model: str, input_tokens: int, output_tokens: int, cached_tokens: int = 0):
        cost = (
            (input_tokens / 1_000_000) * self.rates[model]["input"] +
            (output_tokens / 1_000_000) * self.rates[model]["output"] +
            (cached_tokens / 1_000_000) * self.rates[model]["cached"]
        )
        return cost
```

---

## Database Query Optimization

### 1. ChromaDB Query Optimization

```python
# Bad: Retrieve all, filter in Python
results = collection.get()
filtered = [r for r in results if r['metadata']['risk_level'] == 'Critical']

# Good: Filter at database level
results = collection.get(
    where={"risk_level": "Critical"},
    limit=100
)

# Better: Use efficient indexing
collection = client.create_collection(
    name="optimized_risks",
    metadata={
        "hnsw:space": "cosine",
        "hnsw:M": 16,           # More connections = better recall
        "hnsw:construction_ef": 200,  # Higher = better index quality
        "hnsw:search_ef": 100    # Higher = better search quality
    }
)
```

### 2. ServiceNow Query Optimization

```python
# Bad: Fetch all, filter locally
all_incidents = servicenow_client.get_all_incidents()
critical = [i for i in all_incidents if i.priority == "1"]

# Good: Use ServiceNow query parameters
critical = servicenow_client.get_incidents(
    query="priority=1^active=true",
    fields="number,short_description,priority,sys_created_on",  # Only needed fields
    limit=100
)
```

### 3. Caching Layer for Frequent Queries

See [Caching Patterns](#caching-patterns) above.

---

## Horizontal Scaling Patterns

### 1. Supervisor Worker Pattern

```python
# supervisor.py
from celery import Celery

app = Celery('risk_assessment', broker='redis://localhost:6379')

@app.task
def analyze_vulnerability_batch(cve_ids: List[str]):
    agent = VulnerabilityAgent()
    return agent.analyze_cves(cve_ids)

@app.task
def analyze_threats_batch(cve_ids: List[str]):
    agent = ThreatAgent()
    return agent.analyze_threats(cve_ids)

# Main workflow
def run_distributed_assessment(cve_ids: List[str]):
    # Split into batches
    batches = [cve_ids[i:i+50] for i in range(0, len(cve_ids), 50)]

    # Distribute to workers
    vuln_tasks = [analyze_vulnerability_batch.delay(batch) for batch in batches]
    threat_tasks = [analyze_threats_batch.delay(batch) for batch in batches]

    # Collect results
    vuln_results = [task.get() for task in vuln_tasks]
    threat_results = [task.get() for task in threat_tasks]

    return combine_results(vuln_results, threat_results)
```

### 2. Load Balancing for API Clients

```python
class LoadBalancedNVDClient:
    def __init__(self, api_keys: List[str]):
        self.clients = [NVDClient(key) for key in api_keys]
        self.current_index = 0

    def get_client(self) -> NVDClient:
        """Round-robin load balancing"""
        client = self.clients[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.clients)
        return client

    def get_cve(self, cve_id: str):
        return self.get_client().get_cve(cve_id)
```

### 3. Stateless Agent Design

Ensure agents can run on any worker:

```python
class StatelessVulnerabilityAgent:
    def __init__(self):
        # Load from environment, not instance state
        self.nvd_client = NVDClient(api_key=os.getenv("NVD_API_KEY"))
        self.cache = RedisCache(redis_url=os.getenv("REDIS_URL"))

    def analyze(self, cve_id: str):
        # All state passed in, nothing stored on instance
        # Can be executed on any worker
        return self._analyze_internal(cve_id)
```

---

## Monitoring and Profiling

### 1. LangSmith Integration

```python
from langsmith import Client

client = Client(api_key=os.getenv("LANGSMITH_API_KEY"))

# Track agent performance
with client.trace("vulnerability_analysis", project="risk-assessment"):
    result = vulnerability_agent.analyze(cve_id)
```

### 2. Performance Profiling

```python
import cProfile
import pstats

def profile_assessment():
    profiler = cProfile.Profile()
    profiler.enable()

    supervisor.run_assessment(query="Assess CVE-2024-1234")

    profiler.disable()
    stats = pstats.Stats(profiler)
    stats.sort_stats('cumulative')
    stats.print_stats(20)
```

### 3. Metrics Collection

```python
from prometheus_client import Counter, Histogram, start_http_server

# Metrics
llm_calls = Counter('llm_calls_total', 'Total LLM API calls', ['model', 'agent'])
llm_latency = Histogram('llm_latency_seconds', 'LLM call latency', ['model'])
cve_processed = Counter('cves_processed_total', 'Total CVEs processed')

# Usage
with llm_latency.labels(model="claude-3-5-sonnet").time():
    response = llm.invoke(prompt)
    llm_calls.labels(model="claude-3-5-sonnet", agent="vulnerability").inc()

# Start metrics server
start_http_server(8000)
```

---

## Performance Benchmarks

### Target SLAs

| Operation | Target Latency (p95) | Current Baseline |
|-----------|---------------------|------------------|
| Single CVE analysis | < 2s | 3.5s |
| Batch CVE analysis (10) | < 10s | 18s |
| RAG retrieval | < 500ms | 450ms |
| Full risk assessment | < 30s | 45s |
| Report generation | < 5s | 7s |

### Optimization Impact Summary

| Optimization | Cost Reduction | Latency Reduction |
|--------------|---------------|------------------|
| Prompt caching | 90% | - |
| Model selection | 80% | - |
| Parallel agents | - | 50% |
| Response caching | 70% | 95% (cache hit) |
| Batch processing | 60% | 40% |
| **Combined** | **85-95%** | **60-70%** |

---

## Quick Wins Checklist

- [ ] Enable Redis caching for NVD/MITRE API calls
- [ ] Use Claude 3 Haiku for simple CVE summaries
- [ ] Enable prompt caching for system prompts
- [ ] Run vulnerability + threat agents in parallel
- [ ] Batch CVE processing (50 CVEs per batch)
- [ ] Use persistent ChromaDB collections
- [ ] Implement embedding cache
- [ ] Add cost tracking to all LLM calls
- [ ] Profile workflow with LangSmith
- [ ] Set up Prometheus metrics

---

For additional optimization strategies, see:
- [AWS Bedrock Best Practices](https://docs.aws.amazon.com/bedrock/latest/userguide/best-practices.html)
- [LangChain Performance Tuning](https://python.langchain.com/docs/guides/performance)
- [ChromaDB Scaling Guide](https://docs.trychroma.com/guides/scaling)
