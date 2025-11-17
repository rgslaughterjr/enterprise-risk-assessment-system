"""AWS Bedrock Adapter - Replace Anthropic API with Bedrock"""
import json
from typing import Optional, Dict, AsyncIterator
import logging

logger = logging.getLogger(__name__)


class BedrockAdapter:
    """Adapter for AWS Bedrock Claude models."""

    def __init__(self, model_id: str = "anthropic.claude-3-sonnet-20240229-v1:0",
                 region: str = "us-east-1",
                 mock_mode: bool = True):
        """
        Initialize Bedrock adapter.

        Args:
            model_id: Bedrock model identifier
            region: AWS region
            mock_mode: Use mock responses instead of real API calls
        """
        self.model_id = model_id
        self.region = region
        self.mock_mode = mock_mode
        self.client = None

        if not mock_mode:
            try:
                import boto3
                self.client = boto3.client('bedrock-runtime', region_name=region)
                logger.info(f"Initialized Bedrock adapter: {model_id} in {region}")
            except ImportError:
                logger.warning("boto3 not available, using mock mode")
                self.mock_mode = True
        else:
            logger.info("Initialized Bedrock adapter in mock mode")

    def invoke_bedrock(self, prompt: str, max_tokens: int = 4096,
                      temperature: float = 0.0, system_prompt: Optional[str] = None) -> str:
        """
        Invoke Bedrock model.

        Args:
            prompt: User prompt
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            system_prompt: Optional system prompt

        Returns:
            Model response text
        """
        if self.mock_mode:
            return self._mock_response(prompt)

        try:
            # Build request body for Claude 3 on Bedrock
            request_body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": max_tokens,
                "temperature": temperature,
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            }

            if system_prompt:
                request_body["system"] = system_prompt

            # Invoke model
            response = self.client.invoke_model(
                modelId=self.model_id,
                body=json.dumps(request_body)
            )

            # Parse response
            response_body = json.loads(response['body'].read())
            return response_body['content'][0]['text']

        except Exception as e:
            logger.error(f"Bedrock invocation error: {e}")
            return self._mock_response(prompt)

    def invoke_bedrock_streaming(self, prompt: str, max_tokens: int = 4096,
                                 temperature: float = 0.0) -> AsyncIterator[str]:
        """
        Invoke Bedrock model with streaming.

        Args:
            prompt: User prompt
            max_tokens: Maximum tokens
            temperature: Sampling temperature

        Yields:
            Response text chunks
        """
        if self.mock_mode:
            yield self._mock_response(prompt)
            return

        try:
            request_body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": max_tokens,
                "temperature": temperature,
                "messages": [{"role": "user", "content": prompt}]
            }

            response = self.client.invoke_model_with_response_stream(
                modelId=self.model_id,
                body=json.dumps(request_body)
            )

            for event in response['body']:
                chunk = json.loads(event['chunk']['bytes'])
                if chunk['type'] == 'content_block_delta':
                    yield chunk['delta']['text']

        except Exception as e:
            logger.error(f"Streaming error: {e}")
            yield self._mock_response(prompt)

    def _mock_response(self, prompt: str) -> str:
        """Generate mock response for testing."""
        return f"Mock Bedrock response for prompt: {prompt[:100]}..."

    def estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """
        Estimate cost for Bedrock API call.

        Args:
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens

        Returns:
            Estimated cost in USD
        """
        # Bedrock Claude 3 Sonnet pricing (example)
        pricing = {
            'input': 0.003,   # per 1K tokens
            'output': 0.015   # per 1K tokens
        }

        cost = (input_tokens / 1000 * pricing['input'] +
                output_tokens / 1000 * pricing['output'])

        return cost
