#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Defaults
ENVIRONMENT="dev"
REGION="${REGION:-us-east-1}"
PASSWORD=""
INLINE_REMOTE_IMAGES="false"
NO_CACHE="false"
SKIP_FRONTEND="false"
CONFIRM_PROD="${CONFIRM_PROD:-}"

usage() {
  cat <<EOF
Usage: $0 [--env dev|prod] [--region REGION] [--password VALUE] [--inline-remote-images true|false] [--no-cache] [--skip-frontend]
Environment safety: prod requires CONFIRM_PROD=YES in env.
Examples:
  $0 --env dev
  DEV_APP_PASSWORD=devpass $0 --env dev --inline-remote-images true
  CONFIRM_PROD=YES PROD_APP_PASSWORD=supersecret $0 --env prod
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --env) ENVIRONMENT="$2"; shift 2 ;;
    --region) REGION="$2"; shift 2 ;;
    --password) PASSWORD="$2"; shift 2 ;;
    --inline-remote-images) INLINE_REMOTE_IMAGES="$2"; shift 2 ;;
    --no-cache) NO_CACHE="true"; shift 1 ;;
    --skip-frontend) SKIP_FRONTEND="true"; shift 1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown parameter: $1"; usage; exit 1 ;;
  esac
done

echo "Deploying container (SAM) - environment: ${ENVIRONMENT}"
echo "Region: ${REGION}"
echo "Inline remote images: ${INLINE_REMOTE_IMAGES}"
echo "Frontend deploy: $( [ "$SKIP_FRONTEND" = "true" ] && echo SKIPPED || echo ENABLED )"

# Environment config + safety
case "$ENVIRONMENT" in
  dev)
    STACK_NAME="eml-converter-dev"
    ECR_REPO="eml-converter-dev"
    EFFECTIVE_PASSWORD="${PASSWORD:-${DEV_APP_PASSWORD:-mysecretpassword}}"
    ;;
  prod)
    if [[ "${CONFIRM_PROD}" != "YES" ]]; then
      echo "ERROR: Refusing to deploy prod without CONFIRM_PROD=YES"
      exit 1
    fi
    STACK_NAME="eml-converter"
    ECR_REPO="eml-converter"
    EFFECTIVE_PASSWORD="${PASSWORD:-${PROD_APP_PASSWORD:-}}"
    if [[ -z "${EFFECTIVE_PASSWORD}" ]]; then
      echo "ERROR: No password provided for prod (set PROD_APP_PASSWORD or --password)."
      exit 1
    fi
    ;;
  *)
    echo "Unknown environment: ${ENVIRONMENT} (expected dev|prod)"
    exit 1
    ;;
esac

echo "Stack: ${STACK_NAME}"
echo "ECR repo: ${ECR_REPO}"
echo "Password: $( [ -n "${EFFECTIVE_PASSWORD}" ] && echo '(set, length='"${#EFFECTIVE_PASSWORD}"')' || echo '(empty)' )"

# Docker pre-check
if ! docker info >/dev/null 2>&1; then
  echo "Error: Docker daemon not running."
  exit 1
fi

AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
IMAGE_TAG_TS="$(date +%s)"
IMAGE_TAG_LATEST="latest"
ECR_URI_LATEST="${AWS_ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${ECR_REPO}:${IMAGE_TAG_LATEST}"
ECR_URI_TAGGED="${AWS_ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${ECR_REPO}:${IMAGE_TAG_TS}"

FUNCTION_NAME="eml-converter-${ENVIRONMENT}"

echo "Detecting existing Lambda function arch (if exists)..."
EXISTING_ARCH=$(aws lambda get-function --function-name "${FUNCTION_NAME}" --region "${REGION}" --query 'Configuration.Architectures[0]' --output text 2>/dev/null || echo "x86_64")
[ "${EXISTING_ARCH}" = "None" ] && EXISTING_ARCH="x86_64"

case "${EXISTING_ARCH}" in
  x86_64) DEFAULT_PLATFORM="linux/amd64" ;;
  arm64)  DEFAULT_PLATFORM="linux/arm64" ;;
  *) echo "Unknown arch '${EXISTING_ARCH}', using amd64"; DEFAULT_PLATFORM="linux/amd64" ;;
esac
TARGET_PLATFORM=${TARGET_PLATFORM:-${DEFAULT_PLATFORM}}
echo "Lambda arch reported: ${EXISTING_ARCH} -> building for docker platform: ${TARGET_PLATFORM}"

if ! docker buildx inspect >/dev/null 2>&1; then
  echo "Bootstrapping buildx builder..."
  docker buildx create --use --name emlconv_builder >/dev/null 2>&1 || true
fi

CACHE_FLAG=""
[ "${NO_CACHE}" = "true" ] && CACHE_FLAG="--no-cache" && echo "No-cache build enabled."

echo "Building image..."
docker buildx build \
  ${CACHE_FLAG} \
  --platform "${TARGET_PLATFORM}" \
  -t ${ECR_REPO}:${IMAGE_TAG_LATEST} \
  -f "${SCRIPT_DIR}/Dockerfile" "${PROJECT_ROOT}" \
  --load

echo "Image metadata:"
docker image inspect ${ECR_REPO}:${IMAGE_TAG_LATEST} --format 'ID={{.Id}} Architecture={{.Architecture}} OS={{.Os}}' || true

echo "Ensuring ECR repository exists..."
aws ecr describe-repositories --repository-names ${ECR_REPO} --region ${REGION} >/dev/null 2>&1 || \
  aws ecr create-repository --repository-name ${ECR_REPO} --region ${REGION}

echo "Logging in to ECR..."
aws ecr get-login-password --region ${REGION} | docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com

echo "Tagging & pushing..."
docker tag ${ECR_REPO}:${IMAGE_TAG_LATEST} ${ECR_URI_LATEST}
docker tag ${ECR_REPO}:${IMAGE_TAG_LATEST} ${ECR_URI_TAGGED}
docker push ${ECR_URI_LATEST}
docker push ${ECR_URI_TAGGED}

# Prepare updated template
TEMPLATE_FILE="${SCRIPT_DIR}/template-container.yaml"
UPDATED_TEMPLATE_FILE="${SCRIPT_DIR}/template-updated.yaml"
cp ${TEMPLATE_FILE} ${UPDATED_TEMPLATE_FILE}

# Sanitize template for Image usage
sed -i.bak '/^[[:space:]]*Runtime:/d' ${UPDATED_TEMPLATE_FILE}
sed -i.bak '/^[[:space:]]*Handler:/d' ${UPDATED_TEMPLATE_FILE}
sed -i.bak '/^[[:space:]]*Layers:/d' ${UPDATED_TEMPLATE_FILE}
sed -i.bak '/^[[:space:]]*ImageUri:/d' ${UPDATED_TEMPLATE_FILE}
sed -i.bak '/^[[:space:]]*FunctionName:/d' ${UPDATED_TEMPLATE_FILE}

# Comment out ECRRepository resource
awk '
  BEGIN {skip=0}
  /^  ECRRepository:/ {skip=1; print "# " $0; next}
  skip && /^[ ]{2}[A-Za-z]/ {skip=0}
  skip {print "# " $0; next}
  {print}
' ${UPDATED_TEMPLATE_FILE} > ${UPDATED_TEMPLATE_FILE}.tmp && mv ${UPDATED_TEMPLATE_FILE}.tmp ${UPDATED_TEMPLATE_FILE}

# Inject timestamped image
sed -i.bak "s|PackageType: Image|PackageType: Image\\n      ImageUri: ${ECR_URI_TAGGED}|g" ${UPDATED_TEMPLATE_FILE}

PARAMS="Environment=\"${ENVIRONMENT}\" InlineRemoteImages=\"${INLINE_REMOTE_IMAGES}\""
[ -n "${EFFECTIVE_PASSWORD}" ] && PARAMS="${PARAMS} AppPassword=\"${EFFECTIVE_PASSWORD}\""

echo "Deploying stack via SAM: ${STACK_NAME}"
sam deploy \
  --template-file ${UPDATED_TEMPLATE_FILE} \
  --stack-name "${STACK_NAME}" \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides ${PARAMS} \
  --resolve-image-repos \
  --no-confirm-changeset \
  --region ${REGION} \
  --no-fail-on-empty-changeset

FRONTEND_BUCKET=$(aws cloudformation describe-stacks --stack-name "${STACK_NAME}" --query "Stacks[0].Outputs[?OutputKey=='FrontendBucketName'].OutputValue" --output text --region ${REGION} 2>/dev/null || echo "")
CLOUDFRONT_URL=$(aws cloudformation describe-stacks --stack-name "${STACK_NAME}" --query "Stacks[0].Outputs[?OutputKey=='CloudFrontURL'].OutputValue" --output text --region ${REGION} 2>/dev/null || echo "")

if [[ "${SKIP_FRONTEND}" != "true" && -n "${FRONTEND_BUCKET}" ]]; then
  echo "Building & deploying frontend -> s3://${FRONTEND_BUCKET}"
  ( cd "${PROJECT_ROOT}/frontend"; npm install >/dev/null; npm run build )
  aws s3 sync "${PROJECT_ROOT}/frontend/build/" "s3://${FRONTEND_BUCKET}/" --delete --region ${REGION}
  aws s3 cp "${PROJECT_ROOT}/simple-frontend/index.html" "s3://${FRONTEND_BUCKET}/simple.html" --region ${REGION}
  if [[ -n "${CLOUDFRONT_URL}" && "${CLOUDFRONT_URL}" != "None" ]]; then
    CF_DOMAIN="${CLOUDFRONT_URL#https://}"
    CF_ID=$(aws cloudfront list-distributions --query "DistributionList.Items[?DomainName=='${CF_DOMAIN}'].Id | [0]" --output text 2>/dev/null || echo "")
    if [[ -n "${CF_ID}" && "${CF_ID}" != "None" ]]; then
      echo "Invalidating CloudFront cache: ${CF_ID}"
      aws cloudfront create-invalidation --distribution-id "${CF_ID}" --paths "/*" >/dev/null
    else
      echo "Warning: CloudFront ID not resolved for ${CF_DOMAIN}"
    fi
  fi
else
  echo "Skipping frontend deployment (either SKIP_FRONTEND=true or bucket missing)"
fi

echo "Summary:"
echo "  Environment: ${ENVIRONMENT}"
echo "  Stack:       ${STACK_NAME}"
echo "  Lambda fn:   ${FUNCTION_NAME}"
echo "  ECR image:   ${ECR_URI_TAGGED}"
echo "  Frontend:    ${CLOUDFRONT_URL:-'(none)'}"
echo "Done."
# Cleanup
rm -f ${UPDATED_TEMPLATE_FILE} ${UPDATED_TEMPLATE_FILE}.bak