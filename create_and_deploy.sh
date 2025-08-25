#!/bin/bash
set -e

echo "Creating ECR repository if it doesn't exist and deploying Lambda container with fixes..."

# Verify our fixes are in the local codebase
echo "Verifying code changes..."
grep -n "import asyncio" backend/lambda_function.py
grep -n "fallback_html_to_pdf" backend/lambda_function.py
grep -n "fpdf" backend/requirements.txt

# Setup ECR information
ECR_REPO="eml-converter-dev"
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
AWS_REGION="us-east-1"
ECR_URI="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO}:latest"

# Create ECR repository if it doesn't exist
echo "Creating ECR repository if it doesn't exist..."
aws ecr describe-repositories --repository-names ${ECR_REPO} --region ${AWS_REGION} > /dev/null 2>&1 || aws ecr create-repository --repository-name ${ECR_REPO} --region ${AWS_REGION}

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
echo "Detected Lambda architecture: ${EXISTING_ARCH} -> building image for ${TARGET_PLATFORM}"

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
docker run --rm ${ECR_REPO}:latest cat /var/task/lambda_function.py | grep -n "import asyncio"
docker run --rm ${ECR_REPO}:latest cat /var/task/lambda_function.py | grep -n "fallback_html_to_pdf"

# Login to ECR and push the image
echo "Logging in to ECR..."
aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com

echo "Tagging and pushing Docker image to ECR..."
docker tag ${ECR_REPO}:latest ${ECR_URI}
docker push ${ECR_URI}

# Check if Lambda function exists
echo "Checking if Lambda function exists..."
LAMBDA_EXISTS=$(aws lambda list-functions --region ${AWS_REGION} --query "Functions[?FunctionName==\`eml-converter-dev\`].FunctionName" --output text)

if [ -n "$LAMBDA_EXISTS" ]; then
  # Update existing Lambda function
  echo "Updating existing Lambda function to use the new container image..."
  aws lambda update-function-code \
    --function-name eml-converter-dev \
    --image-uri ${ECR_URI} \
    --region ${AWS_REGION} \
    --publish
else
  # Create new Lambda function
  echo "Creating new Lambda function with the container image..."
  aws lambda create-function \
    --function-name eml-converter-dev \
    --package-type Image \
    --code ImageUri=${ECR_URI} \
    --role arn:aws:iam::${AWS_ACCOUNT_ID}:role/eml-converter-LambdaExecutionRole \
    --region ${AWS_REGION} \
    --timeout 30 \
    --memory-size 1024 \
    --environment Variables="{S3_BUCKET=eml-converter-${AWS_ACCOUNT_ID}-dev,APP_PASSWORD=mysecretpassword}"
fi

echo "Waiting for Lambda update to complete..."
sleep 20  # Give AWS some time to update

# Test the function with a simple request to trigger it
echo "Triggering the Lambda function..."
curl -s -X POST \
  -H "Authorization: Bearer mysecretpassword" \
  -H "X-App-Password: mysecretpassword" \
  -d '{"test": "true"}' \
  "https://d347djbmbuiexy.cloudfront.net/api/auth/check?auth=mysecretpassword"

sleep 10  # Wait for logs to appear

# Get the latest log stream
LATEST_STREAM=$(aws logs describe-log-streams --log-group-name /aws/lambda/eml-converter-dev --order-by LastEventTime --descending --limit 1 --query 'logStreams[0].logStreamName' --output text)

# Get the latest logs
echo "Latest logs from Lambda function:"
aws logs get-log-events --log-group-name /aws/lambda/eml-converter-dev --log-stream-name $LATEST_STREAM --limit 10

echo "Testing the conversion API..."
# Use our test script to verify
bash test_pdf_conversion.sh
