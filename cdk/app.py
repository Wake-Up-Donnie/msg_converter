#!/usr/bin/env python3
"""
CDK App for EML/MSG to PDF Converter with DynamoDB User Management

This CDK app deploys the complete infrastructure including:
- DynamoDB table for user management
- Lambda function (containerized)
- API Gateway
- CloudFront distribution
- S3 buckets
- Automatic whitelisted user creation
"""

import os
from aws_cdk import App, Environment

from stacks.eml_converter_stack import EmlConverterStack

app = App()

# Get environment from context or use default
env_name = app.node.try_get_context("environment") or os.environ.get("ENVIRONMENT", "prod")
aws_region = app.node.try_get_context("region") or os.environ.get("AWS_REGION", "us-east-1")
aws_account = os.environ.get("AWS_ACCOUNT_ID", os.environ.get("CDK_DEFAULT_ACCOUNT"))

# Create environment
env = Environment(
    account=aws_account,
    region=aws_region
)

# Deploy the stack
EmlConverterStack(
    app,
    f"EmlConverterStack-{env_name}",
    env=env,
    environment=env_name,
    description=f"EML/MSG to PDF Converter - {env_name} environment"
)

app.synth()
