#!/bin/bash
set -e

echo "Force rebuilding and redeploying the Lambda container with fixes..."

# Verify our fixes are in the local codebase
echo "Verifying code changes..."
grep -n "import asyncio" backend/lambda_function.py
grep -n "fallback_html_to_pdf" backend/lambda_function.py
grep -n "fpdf" backend/requirements.txt

# First, get the current image URI in ECR to verify update later
ECR_REPO="eml-converter-dev"
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
AWS_REGION="us-east-1"
ECR_URI="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO}:latest"

echo "Current ECR image URI: $ECR_URI"

# Build with --no-cache to force a clean build
FUNCTION_NAME="eml-converter-dev"
EXISTING_ARCH=$(aws lambda get-function --function-name "${FUNCTION_NAME}" --region "${AWS_REGION}" --query 'Configuration.Architectures[0]' --output text 2>/dev/null || echo "x86_64")
if [ "${EXISTING_ARCH}" = "None" ] || [ -z "${EXISTING_ARCH}" ]; then
	EXISTING_ARCH="x86_64"
fi
case "${EXISTING_ARCH}" in
	x86_64) DEFAULT_PLATFORM="linux/amd64" ;;
	arm64)  DEFAULT_PLATFORM="linux/arm64" ;;
	*) echo "Unknown arch '${EXISTING_ARCH}', defaulting to x86_64"; DEFAULT_PLATFORM="linux/amd64" ;;
esac
TARGET_PLATFORM=${TARGET_PLATFORM:-${DEFAULT_PLATFORM}}
echo "Detected Lambda architecture: ${EXISTING_ARCH} -> building for ${TARGET_PLATFORM}"

if ! docker buildx inspect >/dev/null 2>&1; then
	echo "Creating docker buildx builder..."
	docker buildx create --use --name emlconv_builder >/dev/null 2>&1 || true
fi

docker buildx build \
	--no-cache \
	--platform "${TARGET_PLATFORM}" \
	-t ${ECR_REPO}:latest \
	-f aws/Dockerfile . \
	--load

echo "Verifying image architecture:"
docker image inspect ${ECR_REPO}:latest --format 'Architecture={{.Architecture}} OS={{.Os}}' || true

# Explicitly show the lambda_function.py file in the image to verify imports
echo "Verifying lambda_function.py in the container..."
# Override the entrypoint to prevent awslambdaric from running
docker run --rm --entrypoint="grep" "${ECR_REPO}:latest" -i "fpdf" /tmp/requirements.txt
docker run --rm --entrypoint="grep" "${ECR_REPO}:latest" -i "pypdf" /tmp/requirements.txt
docker run --rm --entrypoint="cat" "${ECR_REPO}:latest" /var/task/lambda_function.py | grep -n "import asyncio"

# If verification passes, proceed with deployment
echo "Verification passed. Pushing to ECR and deploying..."
bash aws/deploy-container.sh --password "mysecretpassword" --env dev

echo "Deployment script finished."
echo "Check the AWS console for SAM deployment status and CloudFront invalidation."
