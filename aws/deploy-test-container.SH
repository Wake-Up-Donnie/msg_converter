#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

ENVIRONMENT="test"
REGION=""
PASSWORD=""
INLINE_REMOTE_IMAGES="false"
PROFILE=""
DELETE_STACK=0
USER_SET_REGION=0

usage() {
  cat <<USAGE
Usage: $(basename "$0") [options]

Options:
  --region <aws-region>          AWS region to deploy to (defaults to AWS_REGION/AWS_DEFAULT_REGION)
  --password <password>          Optional password to protect the test UI
  --inline-remote-images <bool>  Enable or disable inlining remote images (default: ${INLINE_REMOTE_IMAGES})
  --profile <aws-profile>        AWS profile to use for all CLI commands
  --delete                       Tear down the test stack and related resources
  --help                         Show this help message

This script always targets the isolated '${ENVIRONMENT}' environment so it never
conflicts with your existing stacks. Run with --delete to clean everything up.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --region)
      REGION="$2"
      USER_SET_REGION=1
      shift 2
      ;;
    --password)
      PASSWORD="$2"
      shift 2
      ;;
    --inline-remote-images)
      INLINE_REMOTE_IMAGES="$2"
      shift 2
      ;;
    --profile)
      PROFILE="$2"
      shift 2
      ;;
    --delete)
      DELETE_STACK=1
      shift 1
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown parameter: $1" >&2
      usage
      exit 1
      ;;
  esac
done

ACTIVE_PROFILE="${PROFILE:-${AWS_PROFILE:-}}"

if [[ -n "${PROFILE}" ]]; then
  export AWS_PROFILE="${PROFILE}"
  echo "Using AWS profile: ${AWS_PROFILE}"
fi

if [[ -z "${REGION}" ]]; then
  if [[ -n "${AWS_REGION:-}" ]]; then
    REGION="${AWS_REGION}"
  elif [[ -n "${AWS_DEFAULT_REGION:-}" ]]; then
    REGION="${AWS_DEFAULT_REGION}"
  else
    if [[ -n "${ACTIVE_PROFILE}" ]]; then
      REGION="$(aws configure get region --profile "${ACTIVE_PROFILE}" 2>/dev/null || true)"
    else
      REGION="$(aws configure get region 2>/dev/null || true)"
    fi
  fi
fi

if [[ -z "${REGION}" ]]; then
  echo "Error: Unable to determine AWS region. Set AWS_REGION or pass --region." >&2
  exit 1
fi

STACK_NAME="eml-converter-${ENVIRONMENT}"
TEMP_BUCKET="eml-converter-temp-${ENVIRONMENT}"
FRONTEND_BUCKET="eml-converter-frontend-${ENVIRONMENT}"
ECR_REPO="eml-converter-${ENVIRONMENT}"

if [[ ${DELETE_STACK} -eq 1 ]]; then
  echo "\n🔻 Deleting test infrastructure for stack '${STACK_NAME}' (region: ${REGION})"

  AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text --region "${REGION}")

  FULL_TEMP_BUCKET="${TEMP_BUCKET}-${AWS_ACCOUNT_ID}"
  FULL_FRONTEND_BUCKET="${FRONTEND_BUCKET}-${AWS_ACCOUNT_ID}"

  for BUCKET in "${FULL_TEMP_BUCKET}" "${FULL_FRONTEND_BUCKET}"; do
    if aws s3api head-bucket --bucket "${BUCKET}" --region "${REGION}" >/dev/null 2>&1; then
      echo "  • Emptying and removing s3://${BUCKET}"
      aws s3 rm "s3://${BUCKET}" --recursive --region "${REGION}" >/dev/null 2>&1 || true
      aws s3 rb "s3://${BUCKET}" --force --region "${REGION}" >/dev/null 2>&1 || true
    else
      echo "  • Bucket s3://${BUCKET} not found (skipping)"
    fi
  done

  if aws ecr describe-repositories --repository-names "${ECR_REPO}" --region "${REGION}" >/dev/null 2>&1; then
    echo "  • Removing ECR repository ${ECR_REPO}"
    aws ecr delete-repository --repository-name "${ECR_REPO}" --force --region "${REGION}" >/dev/null 2>&1 || true
  else
    echo "  • ECR repository ${ECR_REPO} not found (skipping)"
  fi

  if aws cloudformation describe-stacks --stack-name "${STACK_NAME}" --region "${REGION}" >/dev/null 2>&1; then
    echo "  • Running 'sam delete' for ${STACK_NAME}"
    sam delete --stack-name "${STACK_NAME}" --region "${REGION}" --no-prompts || true
  else
    echo "  • Stack ${STACK_NAME} not found (nothing to delete)"
  fi

  echo "\n✅ Test infrastructure cleanup complete."
  exit 0
fi

echo "\n🚀 Deploying isolated test environment (${STACK_NAME})"

CMD=("${SCRIPT_DIR}/deploy-container.sh" "--env" "${ENVIRONMENT}" "--region" "${REGION}" "--inline-remote-images" "${INLINE_REMOTE_IMAGES}")
if [[ -n "${PASSWORD}" ]]; then
  CMD+=("--password" "${PASSWORD}")
fi
if [[ -n "${PROFILE}" ]]; then
  CMD+=("--profile" "${PROFILE}")
fi

"${CMD[@]}"

CF_URL=$(aws cloudformation describe-stacks --stack-name "${STACK_NAME}" --region "${REGION}" --query "Stacks[0].Outputs[?OutputKey=='CloudFrontURL'].OutputValue" --output text 2>/dev/null || true)
API_URL=$(aws cloudformation describe-stacks --stack-name "${STACK_NAME}" --region "${REGION}" --query "Stacks[0].Outputs[?OutputKey=='APIGatewayURL'].OutputValue" --output text 2>/dev/null || true)

echo "\n✅ Test stack deployed."
if [[ -n "${CF_URL}" && "${CF_URL}" != "None" ]]; then
  echo "  • CloudFront URL: ${CF_URL}"
fi
if [[ -n "${API_URL}" && "${API_URL}" != "None" ]]; then
  echo "  • API Gateway URL: ${API_URL}"
fi

echo "\nUse './aws/get_api_urls.sh ${ENVIRONMENT}' to reprint these URLs."

echo "To delete everything created for this test run:"
if [[ ${USER_SET_REGION} -eq 1 ]]; then
  echo "  ${SCRIPT_DIR}/$(basename "$0") --region ${REGION} --delete"
else
  echo "  ${SCRIPT_DIR}/$(basename "$0") --delete"
fi
