"""Tests for AWS Lambda Handler."""

import json
import pytest
from unittest.mock import Mock, patch, MagicMock
from moto import mock_aws
import boto3
from src.deployment import lambda_handler


class TestLambdaResponse:
    """Test suite for Lambda response utilities."""

    def test_lambda_response_success(self):
        """Test successful Lambda response creation."""
        response = lambda_handler.lambda_response(200, {"message": "Success"})

        assert response["statusCode"] == 200
        assert "Content-Type" in response["headers"]
        assert json.loads(response["body"])["message"] == "Success"

    def test_lambda_response_custom_headers(self):
        """Test Lambda response with custom headers."""
        custom_headers = {"X-Custom-Header": "value"}
        response = lambda_handler.lambda_response(200, {}, headers=custom_headers)

        assert response["headers"]["X-Custom-Header"] == "value"
        assert response["headers"]["Content-Type"] == "application/json"

    def test_lambda_response_string_body(self):
        """Test Lambda response with string body."""
        response = lambda_handler.lambda_response(200, "Plain text response")

        assert response["body"] == "Plain text response"


class TestErrorHandling:
    """Test suite for error handling."""

    def test_handle_error_value_error(self):
        """Test handling ValueError."""
        error = ValueError("Invalid input")

        response = lambda_handler.handle_error(error, "Test operation")

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"] == "ValueError"
        assert "Invalid input" in body["message"]

    def test_handle_error_generic(self):
        """Test handling generic exception."""
        error = Exception("Something went wrong")

        response = lambda_handler.handle_error(error, "Test operation")

        assert response["statusCode"] == 500
        body = json.loads(response["body"])
        assert "error" in body


@mock_aws
class TestGetBedrockConfig:
    """Test suite for Bedrock configuration retrieval."""

    def test_get_bedrock_config_success(self):
        """Test successful config retrieval."""
        # Create mock secret
        client = boto3.client('secretsmanager', region_name='us-east-1')
        secret_value = json.dumps({
            'bedrock_model_id': 'claude-3-5-sonnet',
            'max_tokens': 4096
        })

        client.create_secret(
            Name='test-secret',
            SecretString=secret_value
        )

        # Patch environment variable
        with patch.dict('os.environ', {'SECRET_ARN': 'test-secret'}):
            config = lambda_handler.get_bedrock_config()

            assert config['bedrock_model_id'] == 'claude-3-5-sonnet'
            assert config['max_tokens'] == 4096

    def test_get_bedrock_config_fallback(self):
        """Test fallback to default config."""
        with patch.dict('os.environ', {'SECRET_ARN': 'nonexistent-secret'}):
            config = lambda_handler.get_bedrock_config()

            # Should return default config
            assert 'bedrock_model_id' in config
            assert 'max_tokens' in config


@mock_aws
class TestScoreRisk:
    """Test suite for score_risk handler."""

    @pytest.fixture
    def dynamodb_setup(self):
        """Setup DynamoDB table."""
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        table = dynamodb.create_table(
            TableName='risk-assessments-development',
            KeySchema=[
                {'AttributeName': 'assessment_id', 'KeyType': 'HASH'},
                {'AttributeName': 'created_at', 'KeyType': 'RANGE'}
            ],
            AttributeDefinitions=[
                {'AttributeName': 'assessment_id', 'AttributeType': 'S'},
                {'AttributeName': 'created_at', 'AttributeType': 'S'}
            ],
            BillingMode='PAY_PER_REQUEST'
        )
        return table

    def test_score_risk_success(self, dynamodb_setup):
        """Test successful risk scoring."""
        event = {
            'body': json.dumps({
                'risk_id': 'RISK-001',
                'cve': {'id': 'CVE-2024-1234', 'cvss_score': 7.5},
                'asset': {'id': 'ASSET-001'}
            })
        }

        with patch('src.deployment.bedrock_adapter.BedrockAdapter') as MockAdapter:
            mock_adapter = MockAdapter.return_value
            mock_adapter.invoke.return_value = {
                'content': 'Risk assessment result',
                'usage': {'total_tokens': 100}
            }

            response = lambda_handler.score_risk(event, None)

            assert response['statusCode'] == 200
            body = json.loads(response['body'])
            assert 'assessment_id' in body
            assert body['risk_id'] == 'RISK-001'

    def test_score_risk_missing_risk_id(self):
        """Test risk scoring with missing risk_id."""
        event = {'body': json.dumps({})}

        response = lambda_handler.score_risk(event, None)

        assert response['statusCode'] == 400
        body = json.loads(response['body'])
        assert 'error' in body

    def test_score_risk_error_handling(self, dynamodb_setup):
        """Test error handling in risk scoring."""
        event = {
            'body': json.dumps({'risk_id': 'RISK-001'})
        }

        with patch('src.deployment.bedrock_adapter.BedrockAdapter') as MockAdapter:
            MockAdapter.return_value.invoke.side_effect = Exception("Bedrock error")

            response = lambda_handler.score_risk(event, None)

            assert response['statusCode'] == 500


@mock_aws
class TestDiscoverControls:
    """Test suite for discover_controls handler."""

    @pytest.fixture
    def controls_table(self):
        """Setup controls DynamoDB table."""
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        table = dynamodb.create_table(
            TableName='controls-development',
            KeySchema=[{'AttributeName': 'control_id', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'control_id', 'AttributeType': 'S'}],
            BillingMode='PAY_PER_REQUEST'
        )
        return table

    def test_discover_controls_success(self, controls_table):
        """Test successful control discovery."""
        event = {
            'body': json.dumps({
                'sources': ['confluence', 'servicenow']
            })
        }

        response = lambda_handler.discover_controls(event, None)

        assert response['statusCode'] == 200
        body = json.loads(response['body'])
        assert 'controls_discovered' in body
        assert body['controls_discovered'] > 0

    def test_discover_controls_default_sources(self, controls_table):
        """Test control discovery with default sources."""
        event = {'body': json.dumps({})}

        response = lambda_handler.discover_controls(event, None)

        assert response['statusCode'] == 200
        body = json.loads(response['body'])
        assert 'sources' in body


@mock_aws
class TestProcessDocument:
    """Test suite for process_document handler."""

    @pytest.fixture
    def s3_setup(self):
        """Setup S3 bucket."""
        s3 = boto3.client('s3', region_name='us-east-1')
        s3.create_bucket(Bucket='test-bucket')
        return s3

    def test_process_document_from_s3(self, s3_setup):
        """Test document processing from S3 trigger."""
        # Upload test document
        s3_setup.put_object(
            Bucket='test-bucket',
            Key='test-doc.pdf',
            Body=b'Test document content'
        )

        event = {
            'Records': [{
                's3': {
                    'bucket': {'name': 'test-bucket'},
                    'object': {'key': 'test-doc.pdf'}
                }
            }]
        }

        response = lambda_handler.process_document(event, None)

        assert response['statusCode'] == 200
        body = json.loads(response['body'])
        assert 'document_id' in body

    def test_process_document_direct_invocation(self, s3_setup):
        """Test document processing via direct invocation."""
        event = {
            'body': json.dumps({
                'document_content': 'Test document content'
            })
        }

        response = lambda_handler.process_document(event, None)

        assert response['statusCode'] == 200


@mock_aws
class TestToTScoreRisk:
    """Test suite for tot_score_risk handler."""

    @pytest.fixture
    def assessments_table(self):
        """Setup assessments table."""
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        table = dynamodb.create_table(
            TableName='risk-assessments-development',
            KeySchema=[
                {'AttributeName': 'assessment_id', 'KeyType': 'HASH'},
                {'AttributeName': 'created_at', 'KeyType': 'RANGE'}
            ],
            AttributeDefinitions=[
                {'AttributeName': 'assessment_id', 'AttributeType': 'S'},
                {'AttributeName': 'created_at', 'AttributeType': 'S'}
            ],
            BillingMode='PAY_PER_REQUEST'
        )
        return table

    def test_tot_score_risk_success(self, assessments_table):
        """Test successful ToT risk scoring."""
        event = {
            'body': json.dumps({
                'risk_id': 'RISK-TOT-001',
                'num_branches': 5
            })
        }

        with patch('src.deployment.bedrock_adapter.BedrockAdapter') as MockAdapter:
            mock_adapter = MockAdapter.return_value
            mock_adapter.invoke.return_value = {
                'content': 'ToT evaluation',
                'usage': {'total_tokens': 50}
            }

            response = lambda_handler.tot_score_risk(event, None)

            assert response['statusCode'] == 200
            body = json.loads(response['body'])
            assert body['num_branches'] == 5

    def test_tot_score_risk_missing_risk_id(self, assessments_table):
        """Test ToT scoring with missing risk_id."""
        event = {'body': json.dumps({})}

        response = lambda_handler.tot_score_risk(event, None)

        assert response['statusCode'] == 400


@mock_aws
class TestFetchCVEs:
    """Test suite for fetch_cves handler."""

    @pytest.fixture
    def risks_table(self):
        """Setup risks table."""
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        table = dynamodb.create_table(
            TableName='risks-development',
            KeySchema=[{'AttributeName': 'risk_id', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'risk_id', 'AttributeType': 'S'}],
            BillingMode='PAY_PER_REQUEST'
        )
        return table

    def test_fetch_cves_success(self, risks_table):
        """Test successful CVE fetching."""
        event = {
            'body': json.dumps({
                'keywords': ['sql injection'],
                'days_back': 7
            })
        }

        response = lambda_handler.fetch_cves(event, None)

        assert response['statusCode'] == 200
        body = json.loads(response['body'])
        assert 'cves_fetched' in body

    def test_fetch_cves_no_body(self, risks_table):
        """Test CVE fetching without request body."""
        event = {}

        response = lambda_handler.fetch_cves(event, None)

        assert response['statusCode'] == 200


class TestRAGQuery:
    """Test suite for rag_query handler."""

    def test_rag_query_success(self):
        """Test successful RAG query."""
        event = {
            'body': json.dumps({
                'query': 'What are NIST SP 800-53 controls?'
            })
        }

        with patch('src.deployment.bedrock_adapter.BedrockAdapter') as MockAdapter:
            mock_adapter = MockAdapter.return_value
            mock_adapter.invoke.return_value = {
                'content': 'NIST SP 800-53 is a security controls catalog...',
                'usage': {'total_tokens': 150}
            }

            response = lambda_handler.rag_query(event, None)

            assert response['statusCode'] == 200
            body = json.loads(response['body'])
            assert 'answer' in body

    def test_rag_query_missing_query(self):
        """Test RAG query with missing query parameter."""
        event = {'body': json.dumps({})}

        response = lambda_handler.rag_query(event, None)

        assert response['statusCode'] == 400


@mock_aws
class TestOrchestrateAssessment:
    """Test suite for orchestrate_assessment handler."""

    @pytest.fixture
    def orchestration_tables(self):
        """Setup all required tables."""
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')

        # Assessments table
        dynamodb.create_table(
            TableName='risk-assessments-development',
            KeySchema=[
                {'AttributeName': 'assessment_id', 'KeyType': 'HASH'},
                {'AttributeName': 'created_at', 'KeyType': 'RANGE'}
            ],
            AttributeDefinitions=[
                {'AttributeName': 'assessment_id', 'AttributeType': 'S'},
                {'AttributeName': 'created_at', 'AttributeType': 'S'}
            ],
            BillingMode='PAY_PER_REQUEST'
        )

    def test_orchestrate_assessment_success(self, orchestration_tables):
        """Test successful assessment orchestration."""
        event = {
            'body': json.dumps({
                'type': 'full',
                'risks': ['RISK-001', 'RISK-002']
            })
        }

        response = lambda_handler.orchestrate_assessment(event, None)

        assert response['statusCode'] == 200
        body = json.loads(response['body'])
        assert body['status'] == 'completed'
        assert body['total_risks'] == 2

    def test_orchestrate_assessment_partial(self, orchestration_tables):
        """Test partial assessment orchestration."""
        event = {
            'body': json.dumps({
                'type': 'partial',
                'risks': ['RISK-001']
            })
        }

        response = lambda_handler.orchestrate_assessment(event, None)

        assert response['statusCode'] == 200
        body = json.loads(response['body'])
        assert body['type'] == 'partial'
