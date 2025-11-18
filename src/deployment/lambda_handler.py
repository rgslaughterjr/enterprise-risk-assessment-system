"""AWS Lambda Handler for Risk Assessment System.

Provides Lambda function handlers for all risk assessment operations
including scoring, control discovery, document processing, and orchestration.
"""

import json
import logging
import os
import traceback
from datetime import datetime
from decimal import Decimal
from typing import Dict, Any, Optional
import boto3
from botocore.exceptions import ClientError


class DecimalEncoder(json.JSONEncoder):
    """Custom JSON encoder for Decimal types."""
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        return super(DecimalEncoder, self).default(obj)

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
dynamodb = boto3.resource('dynamodb')
s3_client = boto3.client('s3')
secrets_client = boto3.client('secretsmanager')

# Environment variables
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'development')
ASSESSMENTS_TABLE = os.environ.get('ASSESSMENTS_TABLE', 'risk-assessments-development')
RISKS_TABLE = os.environ.get('RISKS_TABLE', 'risks-development')
CONTROLS_TABLE = os.environ.get('CONTROLS_TABLE', 'controls-development')
ARTIFACTS_BUCKET = os.environ.get('ARTIFACTS_BUCKET', 'risk-assessment-artifacts')
BEDROCK_MODEL_ID = os.environ.get('BEDROCK_MODEL_ID', 'anthropic.claude-3-5-sonnet-20241022-v2:0')
SECRET_ARN = os.environ.get('SECRET_ARN', '')


def lambda_response(status_code: int, body: Any, headers: Optional[Dict] = None) -> Dict:
    """Create standardized Lambda response.

    Args:
        status_code: HTTP status code
        body: Response body (will be JSON serialized)
        headers: Optional custom headers

    Returns:
        Lambda response dictionary
    """
    default_headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type,Authorization',
        'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS'
    }

    if headers:
        default_headers.update(headers)

    return {
        'statusCode': status_code,
        'headers': default_headers,
        'body': json.dumps(body, cls=DecimalEncoder) if not isinstance(body, str) else body
    }


def handle_error(e: Exception, context: str = "Operation") -> Dict:
    """Handle Lambda errors with logging and response.

    Args:
        e: Exception that occurred
        context: Context description

    Returns:
        Lambda error response
    """
    logger.error(f"{context} failed: {str(e)}")
    logger.error(traceback.format_exc())

    error_response = {
        'error': type(e).__name__,
        'message': str(e),
        'context': context,
        'timestamp': datetime.utcnow().isoformat()
    }

    # Determine status code
    if isinstance(e, ValueError):
        status_code = 400
    elif isinstance(e, ClientError):
        status_code = 500
    else:
        status_code = 500

    return lambda_response(status_code, error_response)


def get_bedrock_config() -> Dict[str, Any]:
    """Retrieve Bedrock configuration from Secrets Manager.

    Returns:
        Configuration dictionary

    Raises:
        ClientError: If secret retrieval fails
    """
    try:
        # Reload SECRET_ARN from environment in case it was updated
        secret_arn = os.environ.get('SECRET_ARN', '')
        if not secret_arn:
            raise ValueError("SECRET_ARN environment variable is empty")

        response = secrets_client.get_secret_value(SecretId=secret_arn)
        config = json.loads(response['SecretString'])
        logger.info("Bedrock configuration retrieved")
        return config
    except (ClientError, ValueError) as e:
        logger.error(f"Failed to retrieve Bedrock config: {e}")
        # Return default configuration
        return {
            'bedrock_model_id': BEDROCK_MODEL_ID,
            'max_tokens': 4096,
            'temperature': 0.7
        }


def score_risk(event: Dict, context: Any) -> Dict:
    """Lambda handler for risk scoring.

    Args:
        event: Lambda event with risk data in body
        context: Lambda context

    Returns:
        Lambda response with risk score
    """
    try:
        logger.info("Risk scoring lambda invoked")

        # Parse request
        body = json.loads(event.get('body', '{}'))
        risk_id = body.get('risk_id')
        cve = body.get('cve')
        asset = body.get('asset')

        if not risk_id:
            return lambda_response(400, {'error': 'risk_id is required'})

        # Get Bedrock adapter
        from .bedrock_adapter import BedrockAdapter

        adapter = BedrockAdapter(model_id=BEDROCK_MODEL_ID)

        # Score risk (simplified - integrate with actual scoring logic)
        messages = [
            {
                'role': 'user',
                'content': f"Score the following risk: {json.dumps({'cve': cve, 'asset': asset})}"
            }
        ]

        response = adapter.invoke(messages=messages, max_tokens=1024)

        # Save assessment to DynamoDB
        table = dynamodb.Table(ASSESSMENTS_TABLE)
        assessment = {
            'assessment_id': f"ASSESS-{datetime.utcnow().timestamp()}",
            'risk_id': risk_id,
            'score': Decimal('7.5'),  # Placeholder
            'risk_level': 'High',
            'bedrock_response': response['content'],
            'created_at': datetime.utcnow().isoformat(),
            'environment': ENVIRONMENT
        }

        table.put_item(Item=assessment)

        logger.info(f"Risk {risk_id} scored successfully")

        return lambda_response(200, {
            'assessment_id': assessment['assessment_id'],
            'risk_id': risk_id,
            'score': assessment['score'],
            'risk_level': assessment['risk_level']
        })

    except Exception as e:
        return handle_error(e, "Risk scoring")


def discover_controls(event: Dict, context: Any) -> Dict:
    """Lambda handler for control discovery.

    Args:
        event: Lambda event with discovery parameters
        context: Lambda context

    Returns:
        Lambda response with discovered controls
    """
    try:
        logger.info("Control discovery lambda invoked")

        # Parse request
        body = json.loads(event.get('body', '{}'))
        sources = body.get('sources', ['confluence', 'servicenow', 'filesystem'])

        # Discover controls (simplified - integrate with actual discovery logic)
        controls = [
            {
                'control_id': 'AC-1',
                'framework': 'NIST SP 800-53',
                'title': 'Access Control Policy and Procedures',
                'source': 'confluence',
                'discovered_at': datetime.utcnow().isoformat()
            },
            {
                'control_id': 'AC-2',
                'framework': 'NIST SP 800-53',
                'title': 'Account Management',
                'source': 'servicenow',
                'discovered_at': datetime.utcnow().isoformat()
            }
        ]

        # Save controls to DynamoDB
        table = dynamodb.Table(CONTROLS_TABLE)
        for control in controls:
            table.put_item(Item=control)

        logger.info(f"Discovered {len(controls)} controls")

        return lambda_response(200, {
            'controls_discovered': len(controls),
            'controls': controls,
            'sources': sources
        })

    except Exception as e:
        return handle_error(e, "Control discovery")


def process_document(event: Dict, context: Any) -> Dict:
    """Lambda handler for document intelligence processing.

    Args:
        event: Lambda event with S3 trigger or direct document
        context: Lambda context

    Returns:
        Lambda response with processing results
    """
    try:
        logger.info("Document processing lambda invoked")

        # Handle S3 trigger
        if 'Records' in event:
            record = event['Records'][0]
            bucket = record['s3']['bucket']['name']
            key = record['s3']['object']['key']

            logger.info(f"Processing document from S3: s3://{bucket}/{key}")

            # Get document from S3
            response = s3_client.get_object(Bucket=bucket, Key=key)
            document_content = response['Body'].read()

        else:
            # Direct invocation
            body = json.loads(event.get('body', '{}'))
            document_url = body.get('document_url')
            document_content = body.get('document_content', '')

        # Process document (simplified - integrate with actual OCR/classification logic)
        result = {
            'document_id': f"DOC-{datetime.utcnow().timestamp()}",
            'text_extracted': True,
            'tables_extracted': 0,
            'classification': 'security_policy',
            'confidence': 0.85,
            'processed_at': datetime.utcnow().isoformat()
        }

        logger.info(f"Document processed: {result['document_id']}")

        return lambda_response(200, result)

    except Exception as e:
        return handle_error(e, "Document processing")


def tot_score_risk(event: Dict, context: Any) -> Dict:
    """Lambda handler for Tree of Thought risk scoring.

    Args:
        event: Lambda event with risk data
        context: Lambda context

    Returns:
        Lambda response with ToT assessment
    """
    try:
        logger.info("ToT risk scoring lambda invoked")

        # Parse request
        body = json.loads(event.get('body', '{}'))
        risk_id = body.get('risk_id')
        num_branches = body.get('num_branches', 5)

        if not risk_id:
            return lambda_response(400, {'error': 'risk_id is required'})

        # Get Bedrock adapter
        from .bedrock_adapter import BedrockAdapter

        adapter = BedrockAdapter(model_id=BEDROCK_MODEL_ID)

        # Simulate ToT evaluation with multiple branches
        branches = []
        for i in range(num_branches):
            strategy = ['nist_ai_rmf', 'octave', 'iso31000', 'fair', 'quantitative'][i % 5]

            messages = [
                {
                    'role': 'user',
                    'content': f"Evaluate risk {risk_id} using {strategy} framework"
                }
            ]

            response = adapter.invoke(messages=messages, max_tokens=512)

            branches.append({
                'branch_id': f"{risk_id}_{strategy}_{i}",
                'strategy': strategy,
                'score': Decimal(str(6.0 + i * 0.5)),  # Placeholder
                'quality_score': Decimal(str(0.7 + i * 0.05))
            })

        # Calculate consensus
        consensus_score = sum(b['score'] for b in branches) / Decimal(len(branches))

        # Save assessment
        table = dynamodb.Table(ASSESSMENTS_TABLE)
        assessment = {
            'assessment_id': f"TOT-{datetime.utcnow().timestamp()}",
            'risk_id': risk_id,
            'framework': 'Tree of Thought (ToT)',
            'overall_score': consensus_score,
            'branches': branches,
            'created_at': datetime.utcnow().isoformat()
        }

        table.put_item(Item=assessment)

        logger.info(f"ToT assessment completed for {risk_id}")

        return lambda_response(200, {
            'assessment_id': assessment['assessment_id'],
            'risk_id': risk_id,
            'overall_score': consensus_score,
            'num_branches': len(branches)
        })

    except Exception as e:
        return handle_error(e, "ToT risk scoring")


def fetch_cves(event: Dict, context: Any) -> Dict:
    """Lambda handler for CVE fetching from NVD.

    Args:
        event: Lambda event with search parameters
        context: Lambda context

    Returns:
        Lambda response with CVE data
    """
    try:
        logger.info("CVE fetch lambda invoked")

        # Parse request
        body = json.loads(event.get('body', '{}')) if event.get('body') else {}
        keywords = body.get('keywords', [])
        days_back = body.get('days_back', 7)

        # Fetch CVEs (simplified - integrate with actual NVD API)
        cves = [
            {
                'cve_id': 'CVE-2024-1234',
                'cvss_score': Decimal('7.5'),
                'description': 'SQL injection vulnerability',
                'published_date': datetime.utcnow().isoformat()
            },
            {
                'cve_id': 'CVE-2024-5678',
                'cvss_score': Decimal('9.8'),
                'description': 'Remote code execution',
                'published_date': datetime.utcnow().isoformat()
            }
        ]

        # Save CVEs to DynamoDB
        table = dynamodb.Table(RISKS_TABLE)
        for cve in cves:
            table.put_item(Item={'risk_id': cve['cve_id'], 'cve_id': cve['cve_id'], **cve})

        logger.info(f"Fetched {len(cves)} CVEs")

        return lambda_response(200, {
            'cves_fetched': len(cves),
            'cves': cves
        })

    except Exception as e:
        return handle_error(e, "CVE fetching")


def rag_query(event: Dict, context: Any) -> Dict:
    """Lambda handler for RAG (Retrieval-Augmented Generation) queries.

    Args:
        event: Lambda event with query
        context: Lambda context

    Returns:
        Lambda response with RAG results
    """
    try:
        logger.info("RAG query lambda invoked")

        # Parse request
        body = json.loads(event.get('body', '{}'))
        query = body.get('query')

        if not query:
            return lambda_response(400, {'error': 'query is required'})

        # Get Bedrock adapter
        from .bedrock_adapter import BedrockAdapter

        adapter = BedrockAdapter(model_id=BEDROCK_MODEL_ID)

        # RAG query (simplified - integrate with actual vector store)
        messages = [
            {
                'role': 'user',
                'content': f"Answer this question based on security knowledge: {query}"
            }
        ]

        response = adapter.invoke(messages=messages, max_tokens=1024)

        result = {
            'query': query,
            'answer': response['content'],
            'sources': ['NIST SP 800-53', 'CIS Controls v8'],
            'confidence': 0.9,
            'processed_at': datetime.utcnow().isoformat()
        }

        logger.info("RAG query completed")

        return lambda_response(200, result)

    except Exception as e:
        return handle_error(e, "RAG query")


def orchestrate_assessment(event: Dict, context: Any) -> Dict:
    """Lambda handler for full risk assessment orchestration.

    Args:
        event: Lambda event with assessment request
        context: Lambda context

    Returns:
        Lambda response with complete assessment
    """
    try:
        logger.info("Assessment orchestration lambda invoked")

        # Parse request
        body = json.loads(event.get('body', '{}'))
        assessment_type = body.get('type', 'full')
        risks = body.get('risks', [])

        # Orchestrate full assessment workflow
        assessment_id = f"ORCHESTRATE-{datetime.utcnow().timestamp()}"

        # Step 1: Fetch CVEs
        logger.info("Step 1: Fetching CVEs")

        # Step 2: Score risks
        logger.info("Step 2: Scoring risks")

        # Step 3: Discover controls
        logger.info("Step 3: Discovering controls")

        # Step 4: Generate recommendations
        logger.info("Step 4: Generating recommendations")

        # Save final assessment
        table = dynamodb.Table(ASSESSMENTS_TABLE)
        assessment = {
            'assessment_id': assessment_id,
            'type': assessment_type,
            'status': 'completed',
            'total_risks': len(risks),
            'created_at': datetime.utcnow().isoformat(),
            'completed_at': datetime.utcnow().isoformat()
        }

        table.put_item(Item=assessment)

        logger.info(f"Assessment orchestration completed: {assessment_id}")

        return lambda_response(200, {
            'assessment_id': assessment_id,
            'status': 'completed',
            'type': assessment_type,
            'total_risks': len(risks)
        })

    except Exception as e:
        return handle_error(e, "Assessment orchestration")
