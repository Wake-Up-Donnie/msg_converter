#!/bin/bash
set -euo pipefail

# =========================================
# Safe environment-aware deployment script
# =========================================
# Usage:
#   ./create_and_deploy.sh                # deploy to dev (default)
#   ./create_and_deploy.sh dev            # same as above
#   CONFIRM_PROD=YES ./create_and_deploy.sh prod   # deploy to prod (requires explicit confirm)
#
# Optional variables:
#   TARGET_PLATFORM=linux/arm64 (override auto arch)
#   SKIP_TEST=1 (skip post-deploy test invoke)
#   FORCE_NO_CACHE=1 (force --no-cache build)
#
# This script:
#   1. Builds container image
#   2. Pushes to ECR
#   3. Updates (or creates) the Lambda function for the selected environment
#   4. (Optionally) invokes the function directly (not via CloudFront) to warm it
#   5. (Optional) curl environment's CloudFront URL ONLY if provided for that env
#
# Dev/prod config differences are centralized below.

ENVIRONMENT="${1:-dev}"

# -------------------------
# Environment configuration
# -------------------------
case "$ENVIRONMENT" in
  dev)
    LAMBDA_FUNCTION="eml-converter-dev"
    ECR_REPO="eml-converter-dev"
    # Leave CloudFront URL empty unless you have a dev distribution
    CLOUDFRONT_URL="${DEV_CLOUDFRONT_URL:-}"
    APP_PASSWORD="${DEV_APP_PASSWORD:-mysecretpassword}"
    ;;
  prod)
    if [[ "${CONFIRM_PROD:-}" != "YES" ]]; then
      echo "ERROR: Refusing to deploy to prod without CONFIRM_PROD=YES"
      echo "       Example: CONFIRM_PROD=YES ./create_and_deploy.sh prod"
      exit 1
    fi
    LAMBDA_FUNCTION="eml-converter"
    ECR_REPO="eml-converter"
    # Provide the known prod distribution here (user reported this):
    CLOUDFRONT_URL="${PROD_CLOUDFRONT_URL:-https://d347djbmbuiexy.cloudfront.net}"
    APP_PASSWORD="${PROD_APP_PASSWORD:-mysecretpassword}"
    ;;
  *)
    echo "Unknown environment: $ENVIRONMENT (expected dev|prod)"
    exit 1
    ;;
esac

echo "=== Deploying environment: $ENVIRONMENT ==="
echo "Lambda: $LAMBDA_FUNCTION"
echo "ECR repo: $ECR_REPO"
if [[ -n "$CLOUDFRONT_URL" ]]; then
  echo "CloudFront URL: $CLOUDFRONT_URL"
else
  echo "CloudFront URL: (none configured for $ENVIRONMENT)"
fi

# -------------------------
# AWS + build prep
# -------------------------
AWS_REGION="${AWS_REGION:-us-east-1}"
AWS_ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
ECR_URI="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO}:latest"

echo "Verifying code change indicators (non-fatal)..."
grep -n "fallback_html_to_pdf" backend/lambda_function.py || echo "NOTE: 'fallback_html_to_pdf' not found (ok if renamed)."
grep -n "fpdf" backend/requirements.txt || echo "NOTE: 'fpdf' requirement missing?"

echo "Ensuring ECR repository exists..."
aws ecr describe-repositories --repository-names "${ECR_REPO}" --region "${AWS_REGION}" >/dev/null 2>&1 || \
  aws ecr create-repository --repository-name "${ECR_REPO}" --region "${AWS_REGION}" >/dev/null

echo "Determining target architecture..."
EXISTING_ARCH=$(aws lambda get-function --function-name "${LAMBDA_FUNCTION}" --region "${AWS_REGION}" \
  --query 'Configuration.Architectures[0]' --output text 2>/dev/null || echo "x86_64")
if [[ "${EXISTING_ARCH}" == "None" || -z "${EXISTING_ARCH}" ]]; then
  EXISTING_ARCH="x86_64"
fi
case "${EXISTING_ARCH}" in
  x86_64) DEFAULT_PLATFORM="linux/amd64" ;;
  arm64)  DEFAULT_PLATFORM="linux/arm64" ;;
  *) echo "Unknown existing arch '${EXISTING_ARCH}', defaulting to amd64"; DEFAULT_PLATFORM="linux/amd64" ;;
esac
TARGET_PLATFORM="${TARGET_PLATFORM:-$DEFAULT_PLATFORM}"
echo "Building for Lambda arch=${EXISTING_ARCH} -> docker platform=${TARGET_PLATFORM}"

if ! docker info >/dev/null 2>&1; then
  echo "ERROR: Docker daemon not running."
  exit 1
fi

if ! docker buildx inspect >/dev/null 2>&1; then
  echo "Creating docker buildx builder..."
  docker buildx create --use --name emlconv_builder >/dev/null 2>&1 || true
fi

BUILD_NO_CACHE_ARG=""
if [[ "${FORCE_NO_CACHE:-0}" == "1" ]]; then
  BUILD_NO_CACHE_ARG="--no-cache"
  echo "Forcing a no-cache build."
fi

echo "Building image..."
docker buildx build \
  ${BUILD_NO_CACHE_ARG} \
  --platform "${TARGET_PLATFORM}" \
  -t "${ECR_REPO}:latest" \
  -f aws/Dockerfile . \
  --load

echo "Image architecture:"
docker image inspect "${ECR_REPO}:latest" --format '  -> Architecture={{.Architecture}} OS={{.Os}}' || true

echo "Verifying embedded lambda_function.py..."
docker run --rm "${ECR_REPO}:latest" sh -c "grep -n 'handle_auth_check' /var/task/lambda_function.py || echo 'Info: auth handler not found pattern (maybe different name).'" || true

echo "Logging into ECR..."
aws ecr get-login-password --region "${AWS_REGION}" | docker login \
  --username AWS \
  --password-stdin "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"

echo "Tagging & pushing..."
docker tag "${ECR_REPO}:latest" "${ECR_URI}"
docker push "${ECR_URI}"

echo "Checking if Lambda '${LAMBDA_FUNCTION}' exists..."
LAMBDA_EXISTS=$(aws lambda list-functions --region "${AWS_REGION}" \
  --query "Functions[?FunctionName==\`${LAMBDA_FUNCTION}\`].FunctionName" --output text)

ENV_VARS="Variables={S3_BUCKET=eml-converter-${AWS_ACCOUNT_ID}-${ENVIRONMENT},APP_PASSWORD=${APP_PASSWORD}}"

if [[ -n "${LAMBDA_EXISTS}" ]]; then
  echo "Updating existing Lambda function code..."
  aws lambda update-function-code \
    --function-name "${LAMBDA_FUNCTION}" \
    --image-uri "${ECR_URI}" \
    --region "${AWS_REGION}" \
    --publish >/dev/null
else
  echo "Creating new Lambda function ${LAMBDA_FUNCTION}..."
  aws lambda create-function \
    --function-name "${LAMBDA_FUNCTION}" \
    --package-type Image \
    --code ImageUri="${ECR_URI}" \
    --role "arn:aws:iam::${AWS_ACCOUNT_ID}:role/eml-converter-LambdaExecutionRole" \
    --region "${AWS_REGION}" \
    --timeout 60 \
    --memory-size 1024 \
    --architectures "${EXISTING_ARCH}" \
    --environment "${ENV_VARS}" >/dev/null
fi

echo "Waiting for Lambda to finish updating..."
aws lambda wait function-updated --function-name "${LAMBDA_FUNCTION}" --region "${AWS_REGION}"

if [[ "${SKIP_TEST:-0}" != "1" ]]; then
  echo "Invoking Lambda directly (warm-up/auth check)..."
  TMP_OUT=$(mktemp)
  aws lambda invoke \
    --function-name "${LAMBDA_FUNCTION}" \
    --payload '{"path":"/api/auth/check","httpMethod":"POST","headers":{"X-App-Password":"'"${APP_PASSWORD}"'","Authorization":"Bearer '"${APP_PASSWORD}"'"}}' \
    --region "${AWS_REGION}" \
    "${TMP_OUT}" >/dev/null || echo "Lambda invoke returned non-zero."
  echo "Lambda invoke response:"
  cat "${TMP_OUT}"
  rm -f "${TMP_OUT}"
fi

echo "Fetching recent logs..."
LOG_STREAM=$(aws logs describe-log-streams \
  --log-group-name "/aws/lambda/${LAMBDA_FUNCTION}" \
  --order-by LastEventTime --descending --limit 1 \
  --query 'logStreams[0].logStreamName' --output text 2>/dev/null || echo "")
if [[ -n "${LOG_STREAM}" ]]; then
  aws logs get-log-events \
    --log-group-name "/aws/lambda/${LAMBDA_FUNCTION}" \
    --log-stream-name "${LOG_STREAM}" \
    --limit 25 >/dev/null || true
else
  echo "No log stream yet."
fi

# Optional CloudFront test ONLY if configured for env (never use prod URL in dev)
if [[ -n "${CLOUDFRONT_URL}" ]]; then
  echo "Testing CloudFront endpoint auth check..."
  # Hit /api/auth/check with headers (avoid /api/health misuse)
  curl -s -X POST \
    -H "X-App-Password: ${APP_PASSWORD}" \
    -H "Authorization: Bearer ${APP_PASSWORD}" \
    "${CLOUDFRONT_URL}/api/auth/check" || true
else
  echo "Skipping CloudFront test (no URL configured for ${ENVIRONMENT})."
fi

echo "Deployment complete for environment: ${ENVIRONMENT}"