"""Tests for AWS Bedrock Adapter."""

import json
import pytest
from unittest.mock import Mock, patch, MagicMock
from botocore.exceptions import ClientError
from src.deployment.bedrock_adapter import BedrockAdapter, BedrockBatchAdapter


class TestBedrockAdapter:
    """Test suite for BedrockAdapter."""

    @pytest.fixture
    def mock_bedrock_client(self):
        """Create mock Bedrock runtime client."""
        mock_client = Mock()
        mock_response = {
            "body": Mock(read=lambda: json.dumps({
                "id": "msg-123",
                "type": "message",
                "role": "assistant",
                "content": [{"type": "text", "text": "Test response"}],
                "model": "claude-3-5-sonnet",
                "stop_reason": "end_turn",
                "usage": {
                    "input_tokens": 10,
                    "output_tokens": 5
                }
            }).encode())
        }
        mock_client.invoke_model.return_value = mock_response
        return mock_client

    @pytest.fixture
    def adapter(self, mock_bedrock_client):
        """Create Bedrock adapter with mocked client."""
        with patch('boto3.client', return_value=mock_bedrock_client):
            return BedrockAdapter(region_name="us-east-1")

    def test_init_default(self):
        """Test adapter initialization with defaults."""
        with patch('boto3.client') as mock_boto:
            adapter = BedrockAdapter()

            assert adapter.region_name == "us-east-1"
            assert "claude" in adapter.model_id.lower()
            mock_boto.assert_called_once()

    def test_init_custom_region(self):
        """Test adapter initialization with custom region."""
        with patch('boto3.client'):
            adapter = BedrockAdapter(region_name="us-west-2")

            assert adapter.region_name == "us-west-2"

    def test_init_custom_model(self):
        """Test adapter initialization with custom model."""
        with patch('boto3.client'):
            custom_model = "anthropic.claude-3-opus-20240229"
            adapter = BedrockAdapter(model_id=custom_model)

            assert adapter.model_id == custom_model

    def test_init_with_credentials(self):
        """Test adapter initialization with explicit credentials."""
        with patch('boto3.client') as mock_boto:
            adapter = BedrockAdapter(
                aws_access_key_id="AKIATEST",
                aws_secret_access_key="SECRET",
                aws_session_token="TOKEN"
            )

            call_kwargs = mock_boto.call_args[1]
            assert call_kwargs["aws_access_key_id"] == "AKIATEST"
            assert call_kwargs["aws_secret_access_key"] == "SECRET"
            assert call_kwargs["aws_session_token"] == "TOKEN"

    def test_invoke_basic(self, adapter, mock_bedrock_client):
        """Test basic model invocation."""
        messages = [{"role": "user", "content": "Hello"}]

        result = adapter.invoke(messages)

        assert "content" in result
        assert result["content"] == "Test response"
        assert result["role"] == "assistant"
        assert "usage" in result

    def test_invoke_with_parameters(self, adapter, mock_bedrock_client):
        """Test invocation with custom parameters."""
        messages = [{"role": "user", "content": "Test"}]

        result = adapter.invoke(
            messages,
            max_tokens=1000,
            temperature=0.5,
            top_p=0.9,
            system="You are a helpful assistant"
        )

        # Verify request body
        call_args = mock_bedrock_client.invoke_model.call_args
        request_body = json.loads(call_args[1]["body"])

        assert request_body["max_tokens"] == 1000
        assert request_body["temperature"] == 0.5
        assert request_body["top_p"] == 0.9
        assert request_body["system"] == "You are a helpful assistant"

    def test_invoke_with_stop_sequences(self, adapter, mock_bedrock_client):
        """Test invocation with stop sequences."""
        messages = [{"role": "user", "content": "Count to 10"}]
        stop_sequences = ["\n", "STOP"]

        result = adapter.invoke(messages, stop_sequences=stop_sequences)

        call_args = mock_bedrock_client.invoke_model.call_args
        request_body = json.loads(call_args[1]["body"])

        assert request_body["stop_sequences"] == stop_sequences

    def test_invoke_error_handling(self, adapter, mock_bedrock_client):
        """Test error handling during invocation."""
        mock_bedrock_client.invoke_model.side_effect = ClientError(
            {"Error": {"Code": "ValidationException", "Message": "Invalid request"}},
            "InvokeModel"
        )

        messages = [{"role": "user", "content": "Test"}]

        with pytest.raises(ClientError):
            adapter.invoke(messages)

    def test_build_request_body(self, adapter):
        """Test request body building."""
        messages = [{"role": "user", "content": "Test"}]

        body = adapter._build_request_body(
            messages=messages,
            max_tokens=2000,
            temperature=0.8
        )

        assert body["messages"] == messages
        assert body["max_tokens"] == 2000
        assert body["temperature"] == 0.8
        assert "anthropic_version" in body

    def test_transform_response(self, adapter):
        """Test response transformation."""
        raw_response = {
            "id": "msg-456",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "Transformed response"}],
            "model": "claude-3-5-sonnet",
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 20, "output_tokens": 10}
        }

        result = adapter._transform_response(raw_response)

        assert result["content"] == "Transformed response"
        assert result["role"] == "assistant"
        assert result["usage"]["total_tokens"] == 30

    def test_transform_response_multiple_content_blocks(self, adapter):
        """Test transforming response with multiple content blocks."""
        raw_response = {
            "id": "msg-789",
            "content": [
                {"type": "text", "text": "Part 1 "},
                {"type": "text", "text": "Part 2"}
            ],
            "usage": {"input_tokens": 5, "output_tokens": 3}
        }

        result = adapter._transform_response(raw_response)

        assert result["content"] == "Part 1 Part 2"

    def test_count_tokens(self, adapter):
        """Test token counting estimation."""
        text = "This is a test message"

        tokens = adapter.count_tokens(text)

        assert tokens > 0
        assert isinstance(tokens, int)

    def test_get_model_info(self, adapter):
        """Test getting model information."""
        info = adapter.get_model_info()

        assert "model_id" in info
        assert "region" in info
        assert "provider" in info
        assert info["provider"] == "AWS Bedrock"

    def test_test_connection_success(self, adapter, mock_bedrock_client):
        """Test successful connection test."""
        result = adapter.test_connection()

        assert result is True
        mock_bedrock_client.invoke_model.assert_called()

    def test_test_connection_failure(self, adapter, mock_bedrock_client):
        """Test connection test failure."""
        mock_bedrock_client.invoke_model.side_effect = Exception("Connection failed")

        result = adapter.test_connection()

        assert result is False


class TestBedrockStreamingAdapter:
    """Test suite for Bedrock streaming functionality."""

    @pytest.fixture
    def mock_bedrock_client_stream(self):
        """Create mock Bedrock client with streaming support."""
        mock_client = Mock()

        # Create mock event stream
        mock_stream = [
            {
                "chunk": {
                    "bytes": json.dumps({
                        "type": "message_start",
                        "message": {"id": "msg-stream", "role": "assistant"}
                    }).encode()
                }
            },
            {
                "chunk": {
                    "bytes": json.dumps({
                        "type": "content_block_delta",
                        "index": 0,
                        "delta": {"type": "text_delta", "text": "Streaming "}
                    }).encode()
                }
            },
            {
                "chunk": {
                    "bytes": json.dumps({
                        "type": "content_block_delta",
                        "index": 0,
                        "delta": {"type": "text_delta", "text": "response"}
                    }).encode()
                }
            },
            {
                "chunk": {
                    "bytes": json.dumps({
                        "type": "message_stop"
                    }).encode()
                }
            }
        ]

        mock_client.invoke_model_with_response_stream.return_value = {
            "body": mock_stream
        }

        return mock_client

    @pytest.fixture
    def adapter_stream(self, mock_bedrock_client_stream):
        """Create adapter with streaming mock."""
        with patch('boto3.client', return_value=mock_bedrock_client_stream):
            return BedrockAdapter()

    def test_invoke_stream_basic(self, adapter_stream):
        """Test basic streaming invocation."""
        messages = [{"role": "user", "content": "Stream test"}]

        chunks = list(adapter_stream.invoke_stream(messages))

        assert len(chunks) > 0
        assert any(c["type"] == "content_block_delta" for c in chunks)

    def test_invoke_stream_with_parameters(self, adapter_stream, mock_bedrock_client_stream):
        """Test streaming with custom parameters."""
        messages = [{"role": "user", "content": "Test"}]

        list(adapter_stream.invoke_stream(
            messages,
            max_tokens=500,
            temperature=0.3
        ))

        call_args = mock_bedrock_client_stream.invoke_model_with_response_stream.call_args
        request_body = json.loads(call_args[1]["body"])

        assert request_body["max_tokens"] == 500
        assert request_body["temperature"] == 0.3


class TestBedrockBatchAdapter:
    """Test suite for BedrockBatchAdapter."""

    @pytest.fixture
    def mock_adapter(self):
        """Create mock BedrockAdapter."""
        adapter = Mock(spec=BedrockAdapter)
        adapter.invoke.return_value = {
            "content": "Batch response",
            "usage": {"total_tokens": 15}
        }
        return adapter

    @pytest.fixture
    def batch_adapter(self, mock_adapter):
        """Create batch adapter."""
        return BedrockBatchAdapter(
            adapter=mock_adapter,
            max_concurrent=3,
            rate_limit_per_second=5
        )

    def test_init(self, batch_adapter):
        """Test batch adapter initialization."""
        assert batch_adapter.max_concurrent == 3
        assert batch_adapter.rate_limit_per_second == 5

    def test_batch_invoke_single(self, batch_adapter, mock_adapter):
        """Test batch invocation with single request."""
        message_list = [[{"role": "user", "content": "Test 1"}]]

        results = batch_adapter.batch_invoke(message_list)

        assert len(results) == 1
        assert results[0]["content"] == "Batch response"
        mock_adapter.invoke.assert_called_once()

    def test_batch_invoke_multiple(self, batch_adapter, mock_adapter):
        """Test batch invocation with multiple requests."""
        message_list = [
            [{"role": "user", "content": "Test 1"}],
            [{"role": "user", "content": "Test 2"}],
            [{"role": "user", "content": "Test 3"}]
        ]

        results = batch_adapter.batch_invoke(message_list)

        assert len(results) == 3
        assert mock_adapter.invoke.call_count == 3

    def test_batch_invoke_with_parameters(self, batch_adapter, mock_adapter):
        """Test batch invocation with custom parameters."""
        message_list = [[{"role": "user", "content": "Test"}]]

        results = batch_adapter.batch_invoke(
            message_list,
            max_tokens=1000,
            temperature=0.5
        )

        call_kwargs = mock_adapter.invoke.call_args[1]
        assert call_kwargs["max_tokens"] == 1000
        assert call_kwargs["temperature"] == 0.5

    def test_batch_invoke_error_handling(self, batch_adapter, mock_adapter):
        """Test error handling in batch invocation."""
        mock_adapter.invoke.side_effect = [
            {"content": "Success"},
            Exception("Request failed"),
            {"content": "Success"}
        ]

        message_list = [
            [{"role": "user", "content": "Test 1"}],
            [{"role": "user", "content": "Test 2"}],
            [{"role": "user", "content": "Test 3"}]
        ]

        results = batch_adapter.batch_invoke(message_list)

        assert len(results) == 3
        assert results[0]["content"] == "Success"
        assert "error" in results[1]
        assert results[2]["content"] == "Success"
