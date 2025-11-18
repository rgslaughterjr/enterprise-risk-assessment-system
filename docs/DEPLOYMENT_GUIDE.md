# Deployment Guide

Complete guide for deploying the Enterprise Risk Assessment System to production.

**Version:** 1.0.0
**Last Updated:** 2024-11-18
**Target Platform:** AWS (Amazon Web Services)

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Architecture Overview](#architecture)
3. [Local Development Setup](#local-setup)
4. [AWS Deployment](#aws-deployment)
   - [Option 1: AWS Lambda + API Gateway](#lambda-deployment)
   - [Option 2: AWS ECS (Docker)](#ecs-deployment)
   - [Option 3: EC2 Instance](#ec2-deployment)
5. [Configuration Management](#configuration)
6. [Secrets Management](#secrets)
7. [Monitoring & Observability](#monitoring)
8. [Cost Estimates](#costs)
9. [Scaling Considerations](#scaling)
10. [Security Hardening](#security)
11. [Troubleshooting](#troubleshooting)
12. [Maintenance & Updates](#maintenance)

---

<a id='prerequisites'></a>
## 1. Prerequisites

### Required Accounts & Access

- ✅ **AWS Account** with appropriate permissions
- ✅ **Anthropic API Key** (Claude access)
- ✅ **ServiceNow Personal Developer Instance** (or production instance)
- ✅ **API Keys for Threat Intelligence:**
  - NVD API Key (free, obtain from https://nvd.nist.gov/developers/request-an-api-key)
  - VirusTotal API Key (free tier available)
  - AlienVault OTX API Key (free)

### Required Tools

```bash
# AWS CLI
aws --version  # >= 2.x

# Docker (for containerized deployments)
docker --version  # >= 20.x

# Python
python --version  # >= 3.11

# Terraform (optional, for IaC)
terraform --version  # >= 1.5

# Git
git --version
```

### Install AWS CLI

**macOS:**
```bash
brew install awscli
```

**Linux:**
```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
```

**Windows:**
Download installer from https://aws.amazon.com/cli/

**Configure AWS CLI:**
```bash
aws configure
# Enter:
# - AWS Access Key ID
# - AWS Secret Access Key
# - Default region (e.g., us-east-1)
# - Default output format (json)
```

---

<a id='architecture'></a>
## 2. Architecture Overview

### Production Architecture (AWS)

```
┌─────────────────────────────────────────────────────────────────┐
│                         API Gateway                              │
│                    (REST API Endpoint)                           │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Application Layer                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ Lambda Func  │  │ Lambda Func  │  │ Lambda Func  │          │
│  │ (Supervisor) │  │ (Agents)     │  │ (Reports)    │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└────────────────────────────┬────────────────────────────────────┘
                             │
                ┌────────────┴────────────┐
                ▼                         ▼
┌───────────────────────────┐  ┌──────────────────────────┐
│   Vector Store (S3 +      │  │   Secrets Manager        │
│   ChromaDB Persistent)    │  │   (API Keys, Creds)      │
└───────────────────────────┘  └──────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    External APIs                                 │
│  • Anthropic (Claude)                                            │
│  • ServiceNow                                                    │
│  • NVD, VirusTotal, CISA KEV                                     │
│  • MITRE ATT&CK, AlienVault OTX                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Components

1. **API Gateway:** RESTful API endpoint for client requests
2. **Lambda Functions:** Serverless compute for agent orchestration
3. **S3:** Document storage and ChromaDB persistence
4. **Secrets Manager:** Secure API key and credential storage
5. **CloudWatch:** Logging, monitoring, and alerting
6. **VPC (optional):** Network isolation for enhanced security

---

<a id='local-setup'></a>
## 3. Local Development Setup

### Clone Repository

```bash
git clone https://github.com/your-org/enterprise-risk-assessment-system.git
cd enterprise-risk-assessment-system
```

### Create Virtual Environment

```bash
# Create venv
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (Linux/Mac)
source venv/bin/activate
```

### Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Configure Environment

```bash
# Copy example environment file
cp .env.example .env

# Edit .env with your credentials
nano .env  # or use your preferred editor
```

**Required `.env` variables:**
```bash
# LLM
ANTHROPIC_API_KEY=sk-ant-...

# ServiceNow
SERVICENOW_INSTANCE=https://devXXXXX.service-now.com
SERVICENOW_USERNAME=admin
SERVICENOW_PASSWORD=...

# Threat Intelligence
NVD_API_KEY=...
VIRUSTOTAL_API_KEY=...
ALIENVAULT_OTX_KEY=...

# Optional: LangSmith Tracing
LANGSMITH_API_KEY=...
LANGSMITH_TRACING=true
LANGSMITH_PROJECT=enterprise-risk-assessment
```

### Run Tests

```bash
# Run all tests
pytest tests/ -v --ignore=tests/security/ --ignore=tests/reasoning/

# Run with coverage
pytest --cov=src --cov-report=html --cov-report=term

# Open coverage report
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
```

### Test Locally

```bash
# Run demo
python demo_full.py

# Run individual agents
python examples/basic_usage.py
```

---

<a id='aws-deployment'></a>
## 4. AWS Deployment

<a id='lambda-deployment'></a>
### Option 1: AWS Lambda + API Gateway (Recommended for Serverless)

**Best for:** Event-driven workloads, low operational overhead, pay-per-use.

#### Step 1: Package Lambda Function

```bash
# Create deployment package
mkdir -p lambda_package
pip install -r requirements.txt -t lambda_package/
cp -r src lambda_package/
cp -r .env lambda_package/  # Or use Secrets Manager (recommended)

# Create ZIP
cd lambda_package
zip -r ../lambda_function.zip .
cd ..
```

#### Step 2: Create IAM Role

```bash
# Create trust policy
cat > trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

# Create role
aws iam create-role \
  --role-name RiskAssessmentLambdaRole \
  --assume-role-policy-document file://trust-policy.json

# Attach policies
aws iam attach-role-policy \
  --role-name RiskAssessmentLambdaRole \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

aws iam attach-role-policy \
  --role-name RiskAssessmentLambdaRole \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess

aws iam attach-role-policy \
  --role-name RiskAssessmentLambdaRole \
  --policy-arn arn:aws:iam::aws:policy/SecretsManagerReadWrite
```

#### Step 3: Create Lambda Function

```bash
# Get role ARN
ROLE_ARN=$(aws iam get-role --role-name RiskAssessmentLambdaRole --query 'Role.Arn' --output text)

# Create function
aws lambda create-function \
  --function-name risk-assessment-supervisor \
  --runtime python3.11 \
  --role $ROLE_ARN \
  --handler lambda_handler.handler \
  --zip-file fileb://lambda_function.zip \
  --timeout 900 \
  --memory-size 3008 \
  --environment Variables="{ANTHROPIC_API_KEY=sk-ant-...,SERVICENOW_INSTANCE=https://...}"
```

**Create `lambda_handler.py`:**
```python
import json
import os
from src.supervisor.supervisor import RiskAssessmentSupervisor

def handler(event, context):
    """
    Lambda handler for risk assessment.

    Expected event structure:
    {
        "query": "Assess critical vulnerabilities in production",
        "cve_ids": ["CVE-2024-3400", "CVE-2024-21762"]
    }
    """
    try:
        # Parse input
        body = json.loads(event.get('body', '{}'))
        query = body.get('query', '')
        cve_ids = body.get('cve_ids', [])

        # Run assessment
        supervisor = RiskAssessmentSupervisor()
        result = supervisor.run_assessment(query=query, cve_ids=cve_ids)

        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'success': True,
                'data': result
            })
        }

    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({
                'success': False,
                'error': str(e)
            })
        }
```

#### Step 4: Create API Gateway

```bash
# Create REST API
aws apigateway create-rest-api \
  --name risk-assessment-api \
  --description "Enterprise Risk Assessment API"

# Get API ID
API_ID=$(aws apigateway get-rest-apis --query 'items[?name==`risk-assessment-api`].id' --output text)

# Get root resource ID
ROOT_ID=$(aws apigateway get-resources --rest-api-id $API_ID --query 'items[?path==`/`].id' --output text)

# Create /assess resource
aws apigateway create-resource \
  --rest-api-id $API_ID \
  --parent-id $ROOT_ID \
  --path-part assess

# Create POST method
RESOURCE_ID=$(aws apigateway get-resources --rest-api-id $API_ID --query 'items[?path==`/assess`].id' --output text)

aws apigateway put-method \
  --rest-api-id $API_ID \
  --resource-id $RESOURCE_ID \
  --http-method POST \
  --authorization-type NONE

# Integrate with Lambda
aws apigateway put-integration \
  --rest-api-id $API_ID \
  --resource-id $RESOURCE_ID \
  --http-method POST \
  --type AWS_PROXY \
  --integration-http-method POST \
  --uri arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:ACCOUNT_ID:function:risk-assessment-supervisor/invocations

# Deploy API
aws apigateway create-deployment \
  --rest-api-id $API_ID \
  --stage-name prod
```

#### Step 5: Test Deployment

```bash
# Get API endpoint
ENDPOINT="https://${API_ID}.execute-api.us-east-1.amazonaws.com/prod/assess"

# Test request
curl -X POST $ENDPOINT \
  -H "Content-Type: application/json" \
  -d '{
    "query": "Assess critical vulnerabilities",
    "cve_ids": ["CVE-2024-3400"]
  }'
```

---

<a id='ecs-deployment'></a>
### Option 2: AWS ECS (Docker)

**Best for:** Long-running services, complex dependencies, easier local-cloud parity.

#### Step 1: Create Dockerfile

```dockerfile
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    poppler-utils \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY src/ ./src/
COPY examples/ ./examples/

# Expose port
EXPOSE 8000

# Run application
CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

#### Step 2: Build and Push to ECR

```bash
# Create ECR repository
aws ecr create-repository --repository-name risk-assessment-system

# Get repository URI
REPO_URI=$(aws ecr describe-repositories --repository-names risk-assessment-system --query 'repositories[0].repositoryUri' --output text)

# Login to ECR
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin $REPO_URI

# Build image
docker build -t risk-assessment-system .

# Tag image
docker tag risk-assessment-system:latest $REPO_URI:latest

# Push to ECR
docker push $REPO_URI:latest
```

#### Step 3: Create ECS Cluster

```bash
# Create cluster
aws ecs create-cluster --cluster-name risk-assessment-cluster

# Create task definition
cat > task-definition.json <<EOF
{
  "family": "risk-assessment-task",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "2048",
  "memory": "4096",
  "containerDefinitions": [
    {
      "name": "risk-assessment-container",
      "image": "$REPO_URI:latest",
      "portMappings": [
        {
          "containerPort": 8000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {"name": "ANTHROPIC_API_KEY", "value": "sk-ant-..."},
        {"name": "SERVICENOW_INSTANCE", "value": "https://..."}
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/risk-assessment",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
EOF

# Register task definition
aws ecs register-task-definition --cli-input-json file://task-definition.json
```

#### Step 4: Create Service

```bash
# Create service
aws ecs create-service \
  --cluster risk-assessment-cluster \
  --service-name risk-assessment-service \
  --task-definition risk-assessment-task \
  --desired-count 2 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-xxx],securityGroups=[sg-xxx],assignPublicIp=ENABLED}"
```

---

<a id='ec2-deployment'></a>
### Option 3: EC2 Instance

**Best for:** Maximum control, GPU workloads, hybrid cloud.

#### Step 1: Launch EC2 Instance

```bash
# Create key pair
aws ec2 create-key-pair \
  --key-name risk-assessment-key \
  --query 'KeyMaterial' \
  --output text > risk-assessment-key.pem

chmod 400 risk-assessment-key.pem

# Launch instance
aws ec2 run-instances \
  --image-id ami-0c55b159cbfafe1f0 \
  --instance-type t3.xlarge \
  --key-name risk-assessment-key \
  --security-group-ids sg-xxx \
  --subnet-id subnet-xxx \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=risk-assessment-server}]'
```

#### Step 2: SSH and Setup

```bash
# Get public IP
INSTANCE_IP=$(aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=risk-assessment-server" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' \
  --output text)

# SSH to instance
ssh -i risk-assessment-key.pem ubuntu@$INSTANCE_IP

# On instance: Install dependencies
sudo apt update
sudo apt install -y python3.11 python3-pip git tesseract-ocr poppler-utils

# Clone repository
git clone https://github.com/your-org/enterprise-risk-assessment-system.git
cd enterprise-risk-assessment-system

# Install Python dependencies
pip install -r requirements.txt

# Configure environment
nano .env  # Add API keys

# Run with systemd
sudo nano /etc/systemd/system/risk-assessment.service
```

**systemd service file:**
```ini
[Unit]
Description=Risk Assessment System
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/enterprise-risk-assessment-system
ExecStart=/usr/bin/python3 -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
# Start service
sudo systemctl daemon-reload
sudo systemctl start risk-assessment
sudo systemctl enable risk-assessment

# Check status
sudo systemctl status risk-assessment
```

---

<a id='configuration'></a>
## 5. Configuration Management

### AWS Systems Manager Parameter Store

Store non-sensitive configuration:

```bash
aws ssm put-parameter \
  --name /risk-assessment/servicenow-instance \
  --value "https://devXXXXX.service-now.com" \
  --type String

aws ssm put-parameter \
  --name /risk-assessment/log-level \
  --value "INFO" \
  --type String
```

### Retrieve in code:

```python
import boto3

ssm = boto3.client('ssm')

def get_parameter(name):
    response = ssm.get_parameter(Name=name, WithDecryption=True)
    return response['Parameter']['Value']

servicenow_instance = get_parameter('/risk-assessment/servicenow-instance')
```

---

<a id='secrets'></a>
## 6. Secrets Management

### AWS Secrets Manager (Recommended)

```bash
# Create secret
aws secretsmanager create-secret \
  --name risk-assessment/api-keys \
  --secret-string '{
    "anthropic_api_key": "sk-ant-...",
    "nvd_api_key": "...",
    "virustotal_api_key": "...",
    "alienvault_otx_key": "..."
  }'

# Create ServiceNow credentials
aws secretsmanager create-secret \
  --name risk-assessment/servicenow-creds \
  --secret-string '{
    "username": "admin",
    "password": "..."
  }'
```

### Retrieve in code:

```python
import boto3
import json

def get_secret(secret_name):
    client = boto3.client('secretsmanager')
    response = client.get_secret_value(SecretId=secret_name)
    return json.loads(response['SecretString'])

api_keys = get_secret('risk-assessment/api-keys')
anthropic_key = api_keys['anthropic_api_key']
```

### Update Lambda to use Secrets Manager:

```python
# In lambda_handler.py
import os
import boto3
import json

def get_api_keys():
    secret_name = "risk-assessment/api-keys"
    client = boto3.client('secretsmanager')
    response = client.get_secret_value(SecretId=secret_name)
    return json.loads(response['SecretString'])

def handler(event, context):
    # Retrieve secrets
    secrets = get_api_keys()
    os.environ['ANTHROPIC_API_KEY'] = secrets['anthropic_api_key']

    # Continue with assessment...
```

---

<a id='monitoring'></a>
## 7. Monitoring & Observability

### CloudWatch Logs

```bash
# Create log group
aws logs create-log-group --log-group-name /aws/lambda/risk-assessment-supervisor

# Set retention
aws logs put-retention-policy \
  --log-group-name /aws/lambda/risk-assessment-supervisor \
  --retention-in-days 30
```

### CloudWatch Metrics

**Custom metrics:**
```python
import boto3

cloudwatch = boto3.client('cloudwatch')

def publish_metric(metric_name, value, unit='Count'):
    cloudwatch.put_metric_data(
        Namespace='RiskAssessment',
        MetricData=[
            {
                'MetricName': metric_name,
                'Value': value,
                'Unit': unit
            }
        ]
    )

# Example usage
publish_metric('CVEsAnalyzed', 10)
publish_metric('AssessmentDuration', 45.2, 'Seconds')
```

### CloudWatch Alarms

```bash
# Create alarm for Lambda errors
aws cloudwatch put-metric-alarm \
  --alarm-name risk-assessment-errors \
  --alarm-description "Alert on Lambda errors" \
  --metric-name Errors \
  --namespace AWS/Lambda \
  --statistic Sum \
  --period 300 \
  --threshold 5 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 1 \
  --dimensions Name=FunctionName,Value=risk-assessment-supervisor
```

### LangSmith Integration

```python
# Enable in .env
LANGSMITH_API_KEY=...
LANGSMITH_TRACING=true
LANGSMITH_PROJECT=enterprise-risk-assessment

# Automatic tracing for all LangChain/LangGraph calls
```

**Benefits:**
- Trace agent execution paths
- Monitor token usage and costs
- Debug agent failures
- Analyze performance bottlenecks

---

<a id='costs'></a>
## 8. Cost Estimates

### AWS Lambda (Recommended for Most Use Cases)

**Assumptions:**
- 1,000 assessments/month
- 3 minutes per assessment
- 3 GB memory allocation

**Costs:**
```
Lambda Compute: $0.0000166667 per GB-second
= 1,000 × 180s × 3 GB × $0.0000166667
= $9.00/month

API Gateway: $3.50 per million requests
= 1,000 × $0.0000035
= $0.004/month

S3 Storage (ChromaDB): $0.023 per GB
= 10 GB × $0.023
= $0.23/month

Secrets Manager: $0.40 per secret
= 2 secrets × $0.40
= $0.80/month

Total: ~$10/month
```

### AWS ECS Fargate

**Assumptions:**
- 2 tasks running 24/7
- 2 vCPU, 4 GB RAM per task

**Costs:**
```
Fargate vCPU: $0.04048 per vCPU per hour
= 2 tasks × 2 vCPU × 730 hours × $0.04048
= $118/month

Fargate Memory: $0.004445 per GB per hour
= 2 tasks × 4 GB × 730 hours × $0.004445
= $26/month

Total: ~$144/month
```

### EC2 Instance

**Assumptions:**
- t3.xlarge (4 vCPU, 16 GB RAM)
- Running 24/7

**Costs:**
```
EC2 Instance: $0.1664 per hour
= 730 hours × $0.1664
= $121/month

EBS Storage: $0.10 per GB
= 50 GB × $0.10
= $5/month

Total: ~$126/month
```

### External API Costs

**Anthropic Claude:**
- Claude Sonnet: $3/MTok input, $15/MTok output
- Estimated: ~$50-200/month depending on usage

**Threat Intelligence APIs:**
- NVD: Free
- VirusTotal: Free tier (4 req/min) or $500/month premium
- AlienVault OTX: Free

**Total Estimated Monthly Cost:**
- **Low usage:** $60-100/month (Lambda + Claude)
- **Medium usage:** $150-300/month
- **High usage:** $500+/month

---

<a id='scaling'></a>
## 9. Scaling Considerations

### Lambda Auto-Scaling

```bash
# Set reserved concurrency
aws lambda put-function-concurrency \
  --function-name risk-assessment-supervisor \
  --reserved-concurrent-executions 100
```

### ECS Auto-Scaling

```bash
# Register scalable target
aws application-autoscaling register-scalable-target \
  --service-namespace ecs \
  --resource-id service/risk-assessment-cluster/risk-assessment-service \
  --scalable-dimension ecs:service:DesiredCount \
  --min-capacity 2 \
  --max-capacity 10

# Create scaling policy
aws application-autoscaling put-scaling-policy \
  --service-namespace ecs \
  --resource-id service/risk-assessment-cluster/risk-assessment-service \
  --scalable-dimension ecs:service:DesiredCount \
  --policy-name cpu-scaling \
  --policy-type TargetTrackingScaling \
  --target-tracking-scaling-policy-configuration '{
    "TargetValue": 70.0,
    "PredefinedMetricSpecification": {
      "PredefinedMetricType": "ECSServiceAverageCPUUtilization"
    }
  }'
```

### ChromaDB Scaling

**Option 1:** Use S3 for persistence (current setup)
**Option 2:** Migrate to managed vector database (Pinecone, Weaviate)

---

<a id='security'></a>
## 10. Security Hardening

### 1. Enable VPC for Lambda

```bash
# Create VPC
aws ec2 create-vpc --cidr-block 10.0.0.0/16

# Update Lambda configuration
aws lambda update-function-configuration \
  --function-name risk-assessment-supervisor \
  --vpc-config SubnetIds=subnet-xxx,SecurityGroupIds=sg-xxx
```

### 2. Least Privilege IAM

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::risk-assessment-bucket/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
      ],
      "Resource": "arn:aws:secretsmanager:*:*:secret:risk-assessment/*"
    }
  ]
}
```

### 3. Enable API Gateway Authentication

**API Key:**
```bash
aws apigateway create-api-key --name risk-assessment-key --enabled

aws apigateway create-usage-plan \
  --name risk-assessment-plan \
  --api-stages apiId=$API_ID,stage=prod

aws apigateway create-usage-plan-key \
  --usage-plan-id <plan-id> \
  --key-id <api-key-id> \
  --key-type API_KEY
```

**Cognito Authentication (Recommended):**
- Create Cognito User Pool
- Configure API Gateway authorizer
- Require JWT tokens for API access

### 4. Enable Encryption

```bash
# S3 bucket encryption
aws s3api put-bucket-encryption \
  --bucket risk-assessment-bucket \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      }
    }]
  }'

# Enable CloudWatch Logs encryption
aws logs put-log-group \
  --log-group-name /aws/lambda/risk-assessment-supervisor \
  --kms-key-id arn:aws:kms:us-east-1:ACCOUNT_ID:key/KEY_ID
```

---

<a id='troubleshooting'></a>
## 11. Troubleshooting

### Common Issues

#### 1. Lambda Timeout

**Problem:** Function times out after 15 minutes.
**Solution:**
```bash
# Increase timeout (max 15 minutes for Lambda)
aws lambda update-function-configuration \
  --function-name risk-assessment-supervisor \
  --timeout 900

# Or split into smaller functions
```

#### 2. Memory Issues

**Problem:** Lambda runs out of memory.
**Solution:**
```bash
# Increase memory (also increases CPU)
aws lambda update-function-configuration \
  --function-name risk-assessment-supervisor \
  --memory-size 3008
```

#### 3. Rate Limit Errors

**Problem:** NVD/VirusTotal rate limits exceeded.
**Solution:**
- Implement exponential backoff (already in code)
- Use NVD API key for higher limits
- Upgrade VirusTotal tier

#### 4. ChromaDB Persistence

**Problem:** Vector store data lost between Lambda invocations.
**Solution:**
```python
# Mount EFS or use S3 for persistence
import chromadb
from chromadb.config import Settings

client = chromadb.Client(Settings(
    chroma_db_impl="duckdb+parquet",
    persist_directory="/mnt/efs/chromadb"  # EFS mount
))
```

### Logs Debugging

```bash
# View recent logs
aws logs tail /aws/lambda/risk-assessment-supervisor --follow

# Search for errors
aws logs filter-log-events \
  --log-group-name /aws/lambda/risk-assessment-supervisor \
  --filter-pattern "ERROR"

# Get specific invocation logs
aws logs get-log-events \
  --log-group-name /aws/lambda/risk-assessment-supervisor \
  --log-stream-name "2024/11/18/[\$LATEST]..."
```

---

<a id='maintenance'></a>
## 12. Maintenance & Updates

### Rolling Updates (ECS)

```bash
# Update task definition with new image
aws ecs register-task-definition --cli-input-json file://task-definition-v2.json

# Update service
aws ecs update-service \
  --cluster risk-assessment-cluster \
  --service risk-assessment-service \
  --task-definition risk-assessment-task:2
```

### Lambda Version Management

```bash
# Publish new version
aws lambda publish-version --function-name risk-assessment-supervisor

# Create alias
aws lambda create-alias \
  --function-name risk-assessment-supervisor \
  --name prod \
  --function-version 2

# Update API Gateway to use alias
```

### Backup Strategy

```bash
# S3 versioning
aws s3api put-bucket-versioning \
  --bucket risk-assessment-bucket \
  --versioning-configuration Status=Enabled

# Snapshot EBS volumes (EC2)
aws ec2 create-snapshot \
  --volume-id vol-xxx \
  --description "Risk Assessment backup"
```

---

## Additional Resources

- **AWS Documentation:** https://docs.aws.amazon.com/
- **Terraform Examples:** See `infrastructure/terraform/` (if available)
- **CloudFormation Templates:** See `infrastructure/cloudformation/`
- **API Reference:** `docs/API_REFERENCE.md`
- **Architecture Guide:** `CLAUDE.md`

---

## Support

For deployment issues:
1. Check CloudWatch Logs
2. Review IAM permissions
3. Verify environment variables/secrets
4. Test locally first
5. Check AWS service quotas

**Version:** 1.0.0 | **Status:** ✅ Production-ready
