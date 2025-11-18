"""AWS deployment modules for Bedrock and Lambda."""

from .bedrock_adapter import BedrockAdapter, BedrockBatchAdapter

__all__ = ['BedrockAdapter', 'BedrockBatchAdapter']
