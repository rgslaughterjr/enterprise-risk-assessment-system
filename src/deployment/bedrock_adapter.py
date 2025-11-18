"""AWS Bedrock Runtime Adapter.

This module provides an adapter for AWS Bedrock that replaces the Anthropic API
with boto3 bedrock-runtime client. Supports both synchronous and streaming
invocations with Claude models.
"""

import json
import logging
import os
from typing import Dict, Any, List, Optional, Iterator
from datetime import datetime
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


class BedrockAdapter:
    """Adapter for AWS Bedrock runtime API.

    Provides a drop-in replacement for Anthropic API client using
    AWS Bedrock's InvokeModel and InvokeModelWithResponseStream APIs.
    """

    DEFAULT_MODEL_ID = "anthropic.claude-3-5-sonnet-20241022-v2:0"
    DEFAULT_MAX_TOKENS = 4096
    DEFAULT_TEMPERATURE = 0.7
    DEFAULT_TOP_P = 0.9

    def __init__(
        self,
        region_name: Optional[str] = None,
        model_id: Optional[str] = None,
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None,
        aws_session_token: Optional[str] = None,
    ):
        """Initialize Bedrock adapter.

        Args:
            region_name: AWS region (defaults to environment variable or us-east-1)
            model_id: Bedrock model ID (defaults to Claude 3.5 Sonnet)
            aws_access_key_id: AWS access key ID (optional, uses boto3 default chain)
            aws_secret_access_key: AWS secret access key (optional)
            aws_session_token: AWS session token (optional, for temporary credentials)
        """
        self.region_name = region_name or os.environ.get("AWS_REGION", "us-east-1")
        self.model_id = model_id or os.environ.get(
            "BEDROCK_MODEL_ID", self.DEFAULT_MODEL_ID
        )

        # Initialize boto3 client
        session_kwargs = {"region_name": self.region_name}
        if aws_access_key_id:
            session_kwargs["aws_access_key_id"] = aws_access_key_id
        if aws_secret_access_key:
            session_kwargs["aws_secret_access_key"] = aws_secret_access_key
        if aws_session_token:
            session_kwargs["aws_session_token"] = aws_session_token

        self.bedrock_runtime = boto3.client("bedrock-runtime", **session_kwargs)

        logger.info(
            f"Bedrock adapter initialized (region={self.region_name}, model={self.model_id})"
        )

    def invoke(
        self,
        messages: List[Dict[str, Any]],
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        top_p: Optional[float] = None,
        system: Optional[str] = None,
        stop_sequences: Optional[List[str]] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """Invoke Bedrock model (synchronous).

        Args:
            messages: List of message dicts with 'role' and 'content'
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature (0-1)
            top_p: Nucleus sampling parameter
            system: System prompt
            stop_sequences: List of stop sequences
            **kwargs: Additional model parameters

        Returns:
            Response dictionary with 'content', 'usage', and metadata

        Raises:
            ClientError: If Bedrock API call fails
        """
        # Build request body
        request_body = self._build_request_body(
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
            top_p=top_p,
            system=system,
            stop_sequences=stop_sequences,
            **kwargs,
        )

        try:
            logger.info(f"Invoking Bedrock model: {self.model_id}")
            logger.debug(f"Request body: {json.dumps(request_body, indent=2)}")

            response = self.bedrock_runtime.invoke_model(
                modelId=self.model_id,
                contentType="application/json",
                accept="application/json",
                body=json.dumps(request_body),
            )

            # Parse response
            response_body = json.loads(response["body"].read())
            logger.debug(f"Response: {json.dumps(response_body, indent=2)}")

            # Transform to standard format
            result = self._transform_response(response_body)

            logger.info(
                f"Bedrock invocation successful (tokens: {result['usage']['total_tokens']})"
            )

            return result

        except ClientError as e:
            logger.error(f"Bedrock invocation failed: {e}")
            raise

    def invoke_stream(
        self,
        messages: List[Dict[str, Any]],
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        top_p: Optional[float] = None,
        system: Optional[str] = None,
        stop_sequences: Optional[List[str]] = None,
        **kwargs,
    ) -> Iterator[Dict[str, Any]]:
        """Invoke Bedrock model with streaming (async response).

        Args:
            messages: List of message dicts with 'role' and 'content'
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature (0-1)
            top_p: Nucleus sampling parameter
            system: System prompt
            stop_sequences: List of stop sequences
            **kwargs: Additional model parameters

        Yields:
            Response chunks with 'type', 'delta', and metadata

        Raises:
            ClientError: If Bedrock API call fails
        """
        # Build request body
        request_body = self._build_request_body(
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
            top_p=top_p,
            system=system,
            stop_sequences=stop_sequences,
            **kwargs,
        )

        try:
            logger.info(f"Invoking Bedrock model with streaming: {self.model_id}")

            response = self.bedrock_runtime.invoke_model_with_response_stream(
                modelId=self.model_id,
                contentType="application/json",
                accept="application/json",
                body=json.dumps(request_body),
            )

            # Process event stream
            stream = response.get("body")
            if stream:
                for event in stream:
                    chunk = event.get("chunk")
                    if chunk:
                        chunk_data = json.loads(chunk.get("bytes").decode())
                        yield self._transform_stream_chunk(chunk_data)

            logger.info("Bedrock streaming completed")

        except ClientError as e:
            logger.error(f"Bedrock streaming failed: {e}")
            raise

    def _build_request_body(
        self,
        messages: List[Dict[str, Any]],
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        top_p: Optional[float] = None,
        system: Optional[str] = None,
        stop_sequences: Optional[List[str]] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """Build Bedrock request body from parameters.

        Args:
            messages: Message list
            max_tokens: Max tokens
            temperature: Temperature
            top_p: Top-p sampling
            system: System prompt
            stop_sequences: Stop sequences
            **kwargs: Additional parameters

        Returns:
            Request body dictionary
        """
        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "messages": messages,
            "max_tokens": max_tokens or self.DEFAULT_MAX_TOKENS,
        }

        # Optional parameters
        if temperature is not None:
            body["temperature"] = temperature
        else:
            body["temperature"] = self.DEFAULT_TEMPERATURE

        if top_p is not None:
            body["top_p"] = top_p

        if system:
            body["system"] = system

        if stop_sequences:
            body["stop_sequences"] = stop_sequences

        # Additional kwargs
        body.update(kwargs)

        return body

    def _transform_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Transform Bedrock response to standard format.

        Args:
            response: Raw Bedrock response

        Returns:
            Standardized response dictionary
        """
        # Extract content
        content = ""
        if "content" in response and isinstance(response["content"], list):
            for block in response["content"]:
                if block.get("type") == "text":
                    content += block.get("text", "")

        # Extract usage
        usage = response.get("usage", {})

        result = {
            "id": response.get("id", f"bedrock-{datetime.utcnow().timestamp()}"),
            "type": response.get("type", "message"),
            "role": response.get("role", "assistant"),
            "content": content,
            "model": response.get("model", self.model_id),
            "stop_reason": response.get("stop_reason"),
            "stop_sequence": response.get("stop_sequence"),
            "usage": {
                "input_tokens": usage.get("input_tokens", 0),
                "output_tokens": usage.get("output_tokens", 0),
                "total_tokens": usage.get("input_tokens", 0)
                + usage.get("output_tokens", 0),
            },
        }

        return result

    def _transform_stream_chunk(self, chunk: Dict[str, Any]) -> Dict[str, Any]:
        """Transform streaming chunk to standard format.

        Args:
            chunk: Raw streaming chunk

        Returns:
            Standardized chunk dictionary
        """
        chunk_type = chunk.get("type")

        result = {
            "type": chunk_type,
            "index": chunk.get("index", 0),
        }

        if chunk_type == "content_block_delta":
            delta = chunk.get("delta", {})
            if delta.get("type") == "text_delta":
                result["delta"] = {"type": "text", "text": delta.get("text", "")}

        elif chunk_type == "content_block_start":
            content_block = chunk.get("content_block", {})
            if content_block.get("type") == "text":
                result["content_block"] = {"type": "text", "text": ""}

        elif chunk_type == "content_block_stop":
            result["index"] = chunk.get("index", 0)

        elif chunk_type == "message_start":
            message = chunk.get("message", {})
            result["message"] = {
                "id": message.get("id"),
                "type": message.get("type"),
                "role": message.get("role"),
                "model": message.get("model"),
                "usage": message.get("usage", {}),
            }

        elif chunk_type == "message_delta":
            delta = chunk.get("delta", {})
            result["delta"] = {
                "stop_reason": delta.get("stop_reason"),
                "stop_sequence": delta.get("stop_sequence"),
            }
            result["usage"] = chunk.get("usage", {})

        elif chunk_type == "message_stop":
            pass  # End of stream marker

        return result

    def count_tokens(self, text: str) -> int:
        """Estimate token count for text.

        Args:
            text: Input text

        Returns:
            Estimated token count
        """
        # Simple estimation: ~4 characters per token
        return len(text) // 4

    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the configured model.

        Returns:
            Model information dictionary
        """
        return {
            "model_id": self.model_id,
            "region": self.region_name,
            "provider": "AWS Bedrock",
            "max_tokens_default": self.DEFAULT_MAX_TOKENS,
            "temperature_default": self.DEFAULT_TEMPERATURE,
        }

    def test_connection(self) -> bool:
        """Test Bedrock connection with a simple request.

        Returns:
            True if connection successful, False otherwise
        """
        try:
            test_messages = [
                {"role": "user", "content": "Hello"}
            ]

            response = self.invoke(
                messages=test_messages, max_tokens=10, temperature=0.0
            )

            return response is not None and "content" in response

        except Exception as e:
            logger.error(f"Bedrock connection test failed: {e}")
            return False


class BedrockBatchAdapter:
    """Adapter for batch processing with Bedrock.

    Provides utilities for processing multiple requests efficiently
    with rate limiting and error handling.
    """

    def __init__(
        self,
        adapter: BedrockAdapter,
        max_concurrent: int = 5,
        rate_limit_per_second: int = 10,
    ):
        """Initialize batch adapter.

        Args:
            adapter: BedrockAdapter instance
            max_concurrent: Maximum concurrent requests
            rate_limit_per_second: Maximum requests per second
        """
        self.adapter = adapter
        self.max_concurrent = max_concurrent
        self.rate_limit_per_second = rate_limit_per_second

        logger.info(
            f"Batch adapter initialized "
            f"(concurrent={max_concurrent}, rate_limit={rate_limit_per_second}/s)"
        )

    def batch_invoke(
        self,
        message_list: List[List[Dict[str, Any]]],
        **kwargs,
    ) -> List[Dict[str, Any]]:
        """Invoke multiple requests in batch.

        Args:
            message_list: List of message lists
            **kwargs: Common parameters for all requests

        Returns:
            List of responses in same order as inputs
        """
        import time
        from concurrent.futures import ThreadPoolExecutor, as_completed

        results = [None] * len(message_list)
        request_times = []

        with ThreadPoolExecutor(max_workers=self.max_concurrent) as executor:
            # Submit all requests
            future_to_index = {
                executor.submit(self.adapter.invoke, messages, **kwargs): i
                for i, messages in enumerate(message_list)
            }

            # Collect results
            for future in as_completed(future_to_index):
                index = future_to_index[future]

                try:
                    result = future.result()
                    results[index] = result

                    # Rate limiting
                    current_time = time.time()
                    request_times = [
                        t for t in request_times if current_time - t < 1.0
                    ]

                    if len(request_times) >= self.rate_limit_per_second:
                        sleep_time = 1.0 - (current_time - request_times[0])
                        if sleep_time > 0:
                            time.sleep(sleep_time)

                    request_times.append(current_time)

                except Exception as e:
                    logger.error(f"Batch request {index} failed: {e}")
                    results[index] = {"error": str(e)}

        logger.info(
            f"Batch processing completed ({len(message_list)} requests)"
        )

        return results
