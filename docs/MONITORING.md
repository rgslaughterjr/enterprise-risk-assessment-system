# MONITORING GUIDE

Enterprise Risk Assessment System - Production Monitoring

This guide covers CloudWatch setup, metrics tracking, alerting, and performance baselines for the risk assessment system.

## Table of Contents

- [CloudWatch Dashboard Setup](#cloudwatch-dashboard-setup)
- [Key Metrics to Track](#key-metrics-to-track)
- [Alerting Rules](#alerting-rules)
- [Performance Baselines](#performance-baselines)
- [Cost Anomaly Detection](#cost-anomaly-detection)
- [Log Insights Queries](#log-insights-queries)

---

## CloudWatch Dashboard Setup

### 1. Create Dashboard via AWS Console

```bash
# Or use AWS CLI to create dashboard
aws cloudwatch put-dashboard \
  --dashboard-name RiskAssessmentProduction \
  --dashboard-body file://infrastructure/cloudwatch/dashboard.json
```

### 2. Dashboard Configuration (JSON)

Save as `infrastructure/cloudwatch/dashboard.json`:

```json
{
  "widgets": [
    {
      "type": "metric",
      "properties": {
        "title": "Lambda Invocations",
        "metrics": [
          ["AWS/Lambda", "Invocations", {"stat": "Sum", "label": "Total Invocations"}],
          [".", "Errors", {"stat": "Sum", "label": "Errors"}],
          [".", "Throttles", {"stat": "Sum", "label": "Throttles"}]
        ],
        "period": 300,
        "stat": "Sum",
        "region": "us-east-1",
        "yAxis": {
          "left": {"min": 0}
        }
      }
    },
    {
      "type": "metric",
      "properties": {
        "title": "Lambda Duration (p50, p95, p99)",
        "metrics": [
          ["AWS/Lambda", "Duration", {"stat": "p50", "label": "p50"}],
          ["...", {"stat": "p95", "label": "p95"}],
          ["...", {"stat": "p99", "label": "p99"}]
        ],
        "period": 300,
        "region": "us-east-1",
        "yAxis": {
          "left": {"label": "Milliseconds", "min": 0}
        }
      }
    },
    {
      "type": "metric",
      "properties": {
        "title": "API Gateway Latency",
        "metrics": [
          ["AWS/ApiGateway", "Latency", {"stat": "Average", "label": "Average"}],
          ["...", {"stat": "p95", "label": "p95"}],
          ["...", {"stat": "p99", "label": "p99"}]
        ],
        "period": 300,
        "region": "us-east-1",
        "yAxis": {
          "left": {"label": "Milliseconds"}
        }
      }
    },
    {
      "type": "metric",
      "properties": {
        "title": "API Gateway Requests",
        "metrics": [
          ["AWS/ApiGateway", "Count", {"stat": "Sum", "label": "Total Requests"}],
          [".", "4XXError", {"stat": "Sum", "label": "4XX Errors"}],
          [".", "5XXError", {"stat": "Sum", "label": "5XX Errors"}]
        ],
        "period": 300,
        "region": "us-east-1"
      }
    },
    {
      "type": "metric",
      "properties": {
        "title": "Bedrock Model Invocations",
        "metrics": [
          ["AWS/Bedrock", "Invocations", {"stat": "Sum"}],
          [".", "InvocationClientErrors", {"stat": "Sum"}],
          [".", "InvocationServerErrors", {"stat": "Sum"}]
        ],
        "period": 300,
        "region": "us-east-1"
      }
    },
    {
      "type": "log",
      "properties": {
        "title": "Recent Errors",
        "query": "SOURCE '/aws/lambda/RiskAssessmentFunction'\n| fields @timestamp, @message\n| filter @message like /ERROR/\n| sort @timestamp desc\n| limit 20",
        "region": "us-east-1"
      }
    }
  ]
}
```

### 3. Python Script to Create Dashboard

```python
# scripts/setup_monitoring.py
import boto3
import json

def create_cloudwatch_dashboard(dashboard_name: str = "RiskAssessmentProd"):
    """Create CloudWatch dashboard for monitoring."""
    cloudwatch = boto3.client('cloudwatch')

    dashboard_body = {
        "widgets": [
            # Application Metrics
            {
                "type": "metric",
                "properties": {
                    "title": "CVE Processing Rate",
                    "metrics": [
                        ["RiskAssessment", "CVEsProcessed", {"stat": "Sum"}],
                        [".", "CVEProcessingErrors", {"stat": "Sum"}]
                    ],
                    "period": 300,
                    "stat": "Sum",
                    "region": "us-east-1"
                }
            },
            # RAG Performance
            {
                "type": "metric",
                "properties": {
                    "title": "RAG Query Performance",
                    "metrics": [
                        ["RiskAssessment", "RAGQueryLatency", {"stat": "Average"}],
                        ["...", {"stat": "p95"}],
                        ["...", {"stat": "p99"}]
                    ],
                    "period": 300,
                    "region": "us-east-1",
                    "yAxis": {"left": {"label": "ms"}}
                }
            },
            # Agent Execution Times
            {
                "type": "metric",
                "properties": {
                    "title": "Agent Execution Times",
                    "metrics": [
                        ["RiskAssessment", "VulnerabilityAgentDuration", {"stat": "Average"}],
                        [".", "ThreatAgentDuration", {"stat": "Average"}],
                        [".", "RiskScoringAgentDuration", {"stat": "Average"}]
                    ],
                    "period": 300,
                    "region": "us-east-1"
                }
            }
        ]
    }

    response = cloudwatch.put_dashboard(
        DashboardName=dashboard_name,
        DashboardBody=json.dumps(dashboard_body)
    )

    print(f"Dashboard created: {dashboard_name}")
    return response

if __name__ == "__main__":
    create_cloudwatch_dashboard()
```

---

## Key Metrics to Track

### Application-Level Metrics

Publish custom metrics using CloudWatch SDK:

```python
# src/utils/metrics.py
import boto3
from datetime import datetime
from typing import Optional

class MetricsPublisher:
    """Publish custom metrics to CloudWatch."""

    def __init__(self, namespace: str = "RiskAssessment"):
        self.cloudwatch = boto3.client('cloudwatch')
        self.namespace = namespace

    def put_metric(self, metric_name: str, value: float,
                   unit: str = "Count", dimensions: Optional[dict] = None):
        """Publish a single metric."""
        metric_data = {
            'MetricName': metric_name,
            'Value': value,
            'Unit': unit,
            'Timestamp': datetime.utcnow()
        }

        if dimensions:
            metric_data['Dimensions'] = [
                {'Name': k, 'Value': v} for k, v in dimensions.items()
            ]

        self.cloudwatch.put_metric_data(
            Namespace=self.namespace,
            MetricData=[metric_data]
        )

    def record_cve_processed(self, success: bool = True):
        """Record CVE processing metric."""
        metric_name = "CVEsProcessed" if success else "CVEProcessingErrors"
        self.put_metric(metric_name, 1.0)

    def record_agent_duration(self, agent_name: str, duration_ms: float):
        """Record agent execution time."""
        self.put_metric(
            f"{agent_name}AgentDuration",
            duration_ms,
            unit="Milliseconds",
            dimensions={"Agent": agent_name}
        )

    def record_rag_query(self, latency_ms: float, num_results: int):
        """Record RAG query performance."""
        self.put_metric("RAGQueryLatency", latency_ms, unit="Milliseconds")
        self.put_metric("RAGResultsReturned", num_results)

    def record_api_call(self, api_name: str, success: bool, latency_ms: float):
        """Record external API call metrics."""
        status = "Success" if success else "Failure"
        self.put_metric(
            "ExternalAPICall",
            1.0,
            dimensions={"API": api_name, "Status": status}
        )
        self.put_metric(
            "ExternalAPILatency",
            latency_ms,
            unit="Milliseconds",
            dimensions={"API": api_name}
        )
```

### Usage in Agents

```python
# src/agents/vulnerability_agent.py
from src.utils.metrics import MetricsPublisher
import time

class VulnerabilityAgent:
    def __init__(self):
        self.metrics = MetricsPublisher()

    def analyze_cves(self, cve_ids: List[str]):
        start_time = time.time()

        try:
            # ... existing logic ...
            results = [self._analyze_single_cve(cve) for cve in cve_ids]

            # Record success metrics
            duration_ms = (time.time() - start_time) * 1000
            self.metrics.record_agent_duration("Vulnerability", duration_ms)
            self.metrics.record_cve_processed(success=True)

            return results

        except Exception as e:
            self.metrics.record_cve_processed(success=False)
            raise
```

### Critical Metrics to Monitor

| Metric | Target | Alert Threshold | Description |
|--------|--------|----------------|-------------|
| **Lambda Duration (p95)** | <3000ms | >5000ms | 95th percentile execution time |
| **Lambda Errors** | <1% | >5% | Error rate percentage |
| **API Gateway 5XX** | 0 | >10/5min | Server errors |
| **API Gateway Latency (p99)** | <1000ms | >2000ms | End-to-end latency |
| **Bedrock Throttles** | 0 | >5/min | Model rate limiting |
| **CVE Processing Rate** | >50/min | <10/min | Throughput |
| **RAG Query Latency (p95)** | <1200ms | >2500ms | Retrieval performance |
| **External API Errors** | <2% | >10% | NVD, VirusTotal failures |

---

## Alerting Rules

### 1. CloudWatch Alarms (AWS CLI)

```bash
# High error rate alarm
aws cloudwatch put-metric-alarm \
  --alarm-name RiskAssessment-HighErrorRate \
  --alarm-description "Alert when Lambda error rate exceeds 5%" \
  --metric-name Errors \
  --namespace AWS/Lambda \
  --statistic Sum \
  --period 300 \
  --threshold 5 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 2 \
  --dimensions Name=FunctionName,Value=RiskAssessmentFunction \
  --alarm-actions arn:aws:sns:us-east-1:123456789012:ops-alerts

# High latency alarm
aws cloudwatch put-metric-alarm \
  --alarm-name RiskAssessment-HighLatency \
  --alarm-description "Alert when p95 latency exceeds 5 seconds" \
  --metric-name Duration \
  --namespace AWS/Lambda \
  --statistic p95 \
  --period 300 \
  --threshold 5000 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 2 \
  --dimensions Name=FunctionName,Value=RiskAssessmentFunction \
  --alarm-actions arn:aws:sns:us-east-1:123456789012:ops-alerts

# Bedrock throttling alarm
aws cloudwatch put-metric-alarm \
  --alarm-name RiskAssessment-BedrockThrottles \
  --alarm-description "Alert on Bedrock throttling" \
  --metric-name ModelInvocationThrottles \
  --namespace AWS/Bedrock \
  --statistic Sum \
  --period 60 \
  --threshold 5 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 1 \
  --alarm-actions arn:aws:sns:us-east-1:123456789012:ops-alerts
```

### 2. Create Alarms via Python

```python
# scripts/setup_alarms.py
import boto3

def create_alarms(sns_topic_arn: str):
    """Create CloudWatch alarms for production monitoring."""
    cloudwatch = boto3.client('cloudwatch')

    alarms = [
        {
            'AlarmName': 'RiskAssessment-HighErrorRate',
            'MetricName': 'Errors',
            'Namespace': 'AWS/Lambda',
            'Statistic': 'Sum',
            'Period': 300,
            'Threshold': 5.0,
            'ComparisonOperator': 'GreaterThanThreshold',
            'EvaluationPeriods': 2,
            'Dimensions': [
                {'Name': 'FunctionName', 'Value': 'RiskAssessmentFunction'}
            ]
        },
        {
            'AlarmName': 'RiskAssessment-LowThroughput',
            'MetricName': 'CVEsProcessed',
            'Namespace': 'RiskAssessment',
            'Statistic': 'Sum',
            'Period': 300,
            'Threshold': 10.0,
            'ComparisonOperator': 'LessThanThreshold',
            'EvaluationPeriods': 3,
            'TreatMissingData': 'notBreaching'
        },
        {
            'AlarmName': 'RiskAssessment-ExternalAPIFailures',
            'MetricName': 'ExternalAPICall',
            'Namespace': 'RiskAssessment',
            'Statistic': 'Sum',
            'Period': 300,
            'Threshold': 10.0,
            'ComparisonOperator': 'GreaterThanThreshold',
            'EvaluationPeriods': 2,
            'Dimensions': [
                {'Name': 'Status', 'Value': 'Failure'}
            ]
        }
    ]

    for alarm in alarms:
        alarm['AlarmActions'] = [sns_topic_arn]
        cloudwatch.put_metric_alarm(**alarm)
        print(f"Created alarm: {alarm['AlarmName']}")

if __name__ == "__main__":
    # Replace with your SNS topic ARN
    SNS_TOPIC = "arn:aws:sns:us-east-1:123456789012:ops-alerts"
    create_alarms(SNS_TOPIC)
```

### 3. SNS Topic for Notifications

```bash
# Create SNS topic
aws sns create-topic --name ops-alerts

# Subscribe email
aws sns subscribe \
  --topic-arn arn:aws:sns:us-east-1:123456789012:ops-alerts \
  --protocol email \
  --notification-endpoint ops-team@example.com

# Subscribe Slack (via Lambda)
# See: https://docs.aws.amazon.com/chatbot/latest/adminguide/slack-setup.html
```

### 4. Composite Alarms

```python
# Create composite alarm for critical system health
cloudwatch.put_composite_alarm(
    AlarmName='RiskAssessment-CriticalSystemHealth',
    AlarmDescription='Multiple critical issues detected',
    AlarmRule='(ALARM(RiskAssessment-HighErrorRate) OR '
              'ALARM(RiskAssessment-HighLatency)) AND '
              'ALARM(RiskAssessment-LowThroughput)',
    ActionsEnabled=True,
    AlarmActions=[sns_topic_arn]
)
```

---

## Performance Baselines

### Established Baselines (Week 1-7)

Based on testing with 50+ CVEs:

| Metric | p50 | p95 | p99 | Max |
|--------|-----|-----|-----|-----|
| **RAG Query Latency** | 450ms | 1200ms | 2500ms | 3800ms |
| **Vulnerability Agent** | 800ms | 2100ms | 4200ms | 5500ms |
| **Threat Agent** | 650ms | 1800ms | 3500ms | 4800ms |
| **Risk Scoring Agent** | 120ms | 350ms | 680ms | 920ms |
| **Report Generation** | 2200ms | 5100ms | 8400ms | 11000ms |
| **End-to-End Assessment** | 8500ms | 18000ms | 28000ms | 35000ms |

### Throughput Baselines

- **CVE Processing:** 50-60 CVEs/minute
- **Document Processing:** 20-25 documents/minute
- **Concurrent Assessments:** Up to 5 parallel workflows

### Monitoring Baseline Deviations

```python
# src/utils/baseline_monitor.py
from dataclasses import dataclass
from typing import Dict

@dataclass
class PerformanceBaseline:
    """Define performance baselines for monitoring."""
    p50: float
    p95: float
    p99: float
    unit: str = "ms"

BASELINES: Dict[str, PerformanceBaseline] = {
    "rag_query": PerformanceBaseline(p50=450, p95=1200, p99=2500),
    "vulnerability_agent": PerformanceBaseline(p50=800, p95=2100, p99=4200),
    "threat_agent": PerformanceBaseline(p50=650, p95=1800, p99=3500),
    "risk_scoring": PerformanceBaseline(p50=120, p95=350, p99=680),
    "report_generation": PerformanceBaseline(p50=2200, p95=5100, p99=8400),
}

def check_performance_deviation(metric_name: str, value: float,
                                percentile: str = "p95") -> bool:
    """Check if metric exceeds baseline."""
    baseline = BASELINES.get(metric_name)
    if not baseline:
        return False

    threshold = getattr(baseline, percentile)
    deviation_pct = ((value - threshold) / threshold) * 100

    if deviation_pct > 20:  # 20% deviation threshold
        print(f"⚠️ Performance degradation: {metric_name} {percentile}")
        print(f"   Current: {value}ms, Baseline: {threshold}ms")
        print(f"   Deviation: +{deviation_pct:.1f}%")
        return True

    return False
```

---

## Cost Anomaly Detection

### 1. Enable AWS Cost Anomaly Detection

```bash
# Create cost anomaly monitor
aws ce create-anomaly-monitor \
  --anomaly-monitor '{
    "MonitorName": "RiskAssessmentCostMonitor",
    "MonitorType": "DIMENSIONAL",
    "MonitorDimension": "SERVICE"
  }'

# Create subscription for alerts
aws ce create-anomaly-subscription \
  --anomaly-subscription '{
    "SubscriptionName": "RiskAssessmentCostAlerts",
    "Threshold": 50.0,
    "Frequency": "DAILY",
    "MonitorArnList": ["arn:aws:ce::123456789012:anomalymonitor/..."],
    "Subscribers": [
      {
        "Type": "EMAIL",
        "Address": "ops-team@example.com"
      }
    ]
  }'
```

### 2. Monitor Key Cost Drivers

```python
# scripts/cost_analysis.py
import boto3
from datetime import datetime, timedelta

def get_cost_breakdown(days: int = 7):
    """Get cost breakdown by service."""
    ce = boto3.client('ce')

    end_date = datetime.utcnow().date()
    start_date = end_date - timedelta(days=days)

    response = ce.get_cost_and_usage(
        TimePeriod={
            'Start': start_date.isoformat(),
            'End': end_date.isoformat()
        },
        Granularity='DAILY',
        Metrics=['UnblendedCost'],
        GroupBy=[
            {'Type': 'DIMENSION', 'Key': 'SERVICE'}
        ]
    )

    # Parse results
    costs = {}
    for result in response['ResultsByTime']:
        date = result['TimePeriod']['Start']
        for group in result['Groups']:
            service = group['Keys'][0]
            cost = float(group['Metrics']['UnblendedCost']['Amount'])
            costs.setdefault(service, []).append((date, cost))

    # Print top services by cost
    total_costs = {svc: sum(c for _, c in vals) for svc, vals in costs.items()}
    sorted_costs = sorted(total_costs.items(), key=lambda x: x[1], reverse=True)

    print(f"\nCost breakdown (last {days} days):")
    print("-" * 50)
    total = 0
    for service, cost in sorted_costs[:10]:
        print(f"{service:30} ${cost:>10.2f}")
        total += cost
    print("-" * 50)
    print(f"{'TOTAL':30} ${total:>10.2f}")

    return costs

if __name__ == "__main__":
    get_cost_breakdown(days=30)
```

### 3. Expected Cost Profile (Monthly)

| Service | Estimated Cost | Notes |
|---------|---------------|-------|
| **Bedrock (Claude)** | $150-300 | ~1M tokens/day @ $3/MTok |
| **Lambda** | $20-40 | 100K invocations, 3GB memory |
| **API Gateway** | $5-10 | 100K requests |
| **CloudWatch** | $10-15 | Logs + metrics |
| **S3** | $2-5 | Document storage |
| **Total** | **$187-370** | Based on moderate usage |

### 4. Cost Optimization Alerts

```python
# Lambda function for cost monitoring
import json
import boto3

def lambda_handler(event, context):
    """Alert on unexpected cost increases."""
    ce = boto3.client('ce')
    sns = boto3.client('sns')

    # Get yesterday's cost
    end = datetime.utcnow().date()
    start = end - timedelta(days=1)

    response = ce.get_cost_and_usage(
        TimePeriod={'Start': start.isoformat(), 'End': end.isoformat()},
        Granularity='DAILY',
        Metrics=['UnblendedCost']
    )

    daily_cost = float(response['ResultsByTime'][0]['Total']['UnblendedCost']['Amount'])

    # Alert if daily cost exceeds threshold
    DAILY_THRESHOLD = 15.0  # $15/day = ~$450/month
    if daily_cost > DAILY_THRESHOLD:
        message = f"""
        🚨 High Daily AWS Cost Alert

        Date: {start}
        Cost: ${daily_cost:.2f}
        Threshold: ${DAILY_THRESHOLD:.2f}

        Please review AWS Cost Explorer for details.
        """

        sns.publish(
            TopicArn=os.environ['SNS_TOPIC_ARN'],
            Subject='High AWS Cost Alert - Risk Assessment System',
            Message=message
        )

    return {'statusCode': 200, 'body': json.dumps(f'Daily cost: ${daily_cost:.2f}')}
```

---

## Log Insights Queries

### Useful CloudWatch Logs Insights Queries

#### 1. Error Analysis

```sql
# Find all errors with context
fields @timestamp, @message, @logStream
| filter @message like /ERROR/
| sort @timestamp desc
| limit 50

# Group errors by type
fields @message
| filter @message like /ERROR/
| parse @message /ERROR - (?<error_type>.*?):/
| stats count() by error_type
| sort count desc
```

#### 2. Performance Analysis

```sql
# Lambda cold starts
fields @timestamp, @initDuration
| filter @type = "REPORT"
| stats avg(@initDuration), max(@initDuration), pct(@initDuration, 95)

# Slow queries (>2 seconds)
fields @timestamp, @message, @duration
| filter @message like /Duration/
| parse @message "Duration: * ms" as duration
| filter duration > 2000
| sort duration desc
| limit 25

# Agent execution times
fields @timestamp, agent_name, duration_ms
| filter @message like /Agent execution/
| parse @message "Agent: *, Duration: *ms" as agent_name, duration_ms
| stats avg(duration_ms), max(duration_ms), pct(duration_ms, 95) by agent_name
```

#### 3. API Call Analysis

```sql
# External API failures
fields @timestamp, api_name, error
| filter @message like /API call failed/
| parse @message "API: *, Error: *" as api_name, error
| stats count() by api_name, error

# Rate limit hits
fields @timestamp, @message
| filter @message like /rate limit/i
| stats count() by bin(5m)
```

#### 4. CVE Processing

```sql
# CVE processing volume
fields @timestamp, cve_id
| filter @message like /Processing CVE/
| parse @message "CVE: *" as cve_id
| stats count() by bin(1h)

# Failed CVE analyses
fields @timestamp, cve_id, error
| filter @message like /CVE analysis failed/
| parse @message "CVE: *, Error: *" as cve_id, error
| stats count() by error
```

---

## Monitoring Best Practices

### 1. Dashboard Review Cadence

- **Daily:** Check error rates, latency, throughput
- **Weekly:** Review cost trends, performance baselines
- **Monthly:** Analyze usage patterns, optimize resources

### 2. Alert Response Procedures

**High Error Rate:**
1. Check CloudWatch Logs for error details
2. Review recent deployments
3. Verify external API status (NVD, VirusTotal)
4. Check ServiceNow instance availability

**High Latency:**
1. Identify slow agents via metrics
2. Check for RAG query performance degradation
3. Review Bedrock model throttling
4. Analyze concurrent execution count

**Low Throughput:**
1. Check for rate limiting on external APIs
2. Review Lambda concurrency settings
3. Verify no stuck executions
4. Check for memory constraints

### 3. Continuous Improvement

```python
# Weekly performance report
def generate_weekly_report():
    """Generate automated performance report."""
    metrics = {
        'cves_processed': get_metric_sum('CVEsProcessed', days=7),
        'avg_latency': get_metric_avg('RAGQueryLatency', days=7),
        'error_rate': get_error_rate(days=7),
        'total_cost': get_weekly_cost()
    }

    report = f"""
    Weekly Performance Report
    =========================

    CVEs Processed: {metrics['cves_processed']}
    Avg RAG Latency: {metrics['avg_latency']:.0f}ms
    Error Rate: {metrics['error_rate']:.2f}%
    Weekly Cost: ${metrics['total_cost']:.2f}

    Action Items:
    {generate_action_items(metrics)}
    """

    send_email(to='ops-team@example.com', subject='Weekly Report', body=report)
```

---

## Additional Resources

- [AWS CloudWatch Documentation](https://docs.aws.amazon.com/cloudwatch/)
- [AWS Cost Management](https://aws.amazon.com/aws-cost-management/)
- [LangSmith Tracing](https://docs.smith.langchain.com/)
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Error resolution guide
