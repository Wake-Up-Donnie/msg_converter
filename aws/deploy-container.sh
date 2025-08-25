#!/bin/bash
set -e

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Default values
ENVIRONMENT="dev"
REGION="us-east-1"
PASSWORD=""
INLINE_REMOTE_IMAGES="false"

# Parse command line arguments
while [ "$#" -gt 0 ]; do
  case "$1" in
    --env)
      ENVIRONMENT="$2"
      shift 2
      ;;
    --region)
      REGION="$2"
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
    *)
      echo "Unknown parameter: $1"
      exit 1
      ;;
  esac
done

echo "Deploying container-based solution for environment: $ENVIRONMENT"
echo "AWS Region: $REGION"

# Check if Docker daemon is running
if ! docker info > /dev/null 2>&1; then
  echo "Error: Docker daemon is not running."
  echo "Please start Docker Desktop or the Docker service before running this script."
  exit 1
fi
echo "Docker daemon is running - continuing with deployment..."

# Get AWS account ID
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
if [ $? -ne 0 ]; then
  echo "Error: Failed to get AWS account ID. Make sure you're logged in to AWS CLI."
  exit 1
fi

# Set ECR repository name and image tags
ECR_REPO="eml-converter-${ENVIRONMENT}"
# Unique tag to force Lambda update each deploy
IMAGE_TAG_TS="$(date +%s)"
IMAGE_TAG_LATEST="latest"
ECR_URI_LATEST="${AWS_ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${ECR_REPO}:${IMAGE_TAG_LATEST}"
ECR_URI_TAGGED="${AWS_ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${ECR_REPO}:${IMAGE_TAG_TS}"
FUNCTION_NAME="eml-converter-${ENVIRONMENT}"
echo "Detecting existing Lambda architecture (if function exists): ${FUNCTION_NAME}";
EXISTING_ARCH=$(aws lambda get-function --function-name "${FUNCTION_NAME}" --region "${REGION}" --query 'Configuration.Architectures[0]' --output text 2>/dev/null || echo "x86_64")
if [ "${EXISTING_ARCH}" = "None" ] || [ -z "${EXISTING_ARCH}" ]; then
  EXISTING_ARCH="x86_64"
fi
case "${EXISTING_ARCH}" in
  x86_64) DEFAULT_PLATFORM="linux/amd64" ;;
  arm64)  DEFAULT_PLATFORM="linux/arm64" ;;
  *) echo "Unknown reported arch '${EXISTING_ARCH}', defaulting to x86_64"; DEFAULT_PLATFORM="linux/amd64" ;;
esac

TARGET_PLATFORM=${TARGET_PLATFORM:-${DEFAULT_PLATFORM}}
echo "Lambda architecture (reported/default): ${EXISTING_ARCH} -> building image for platform: ${TARGET_PLATFORM}";

if ! docker buildx inspect >/dev/null 2>&1; then
  echo "Creating and bootstrapping a docker buildx builder instance..."
  docker buildx create --use --name emlconv_builder >/dev/null 2>&1 || true
fi

docker buildx build \
  --platform "${TARGET_PLATFORM}" \
  -t ${ECR_REPO}:${IMAGE_TAG_LATEST} \
  -f "${SCRIPT_DIR}/Dockerfile" "${PROJECT_ROOT}" \
  --load

echo "Verifying built image architecture:"
docker image inspect ${ECR_REPO}:${IMAGE_TAG_LATEST} --format 'ID={{.Id}} Architecture={{.Architecture}} OS={{.Os}}' || true

# Check if the ECR repository exists, create it if it doesn't
aws ecr describe-repositories --repository-names ${ECR_REPO} --region ${REGION} > /dev/null 2>&1
if [ $? -ne 0 ]; then
  echo "Creating ECR repository: ${ECR_REPO}"
  aws ecr create-repository --repository-name ${ECR_REPO} --region ${REGION}
fi

# Login to ECR
echo "Logging in to ECR..."
aws ecr get-login-password --region ${REGION} | docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com

# Tag and push the Docker image
echo "Tagging and pushing Docker image to ECR..."
# Tag as both latest and a unique timestamped tag
docker tag ${ECR_REPO}:${IMAGE_TAG_LATEST} ${ECR_URI_LATEST}
docker tag ${ECR_REPO}:${IMAGE_TAG_LATEST} ${ECR_URI_TAGGED}
docker push ${ECR_URI_LATEST}
docker push ${ECR_URI_TAGGED}

# Update the SAM template with the correct image URI
echo "Updating SAM template with the container image URI..."
TEMPLATE_FILE="${SCRIPT_DIR}/template-container.yaml"
UPDATED_TEMPLATE_FILE="${SCRIPT_DIR}/template-updated.yaml"

# Create a temporary template file with the correct image URI
cp ${TEMPLATE_FILE} ${UPDATED_TEMPLATE_FILE}

# Remove incompatible fields for Image package type (Runtime/Handler/Layers)
sed -i.bak '/^[[:space:]]*Runtime:/d' ${UPDATED_TEMPLATE_FILE}
sed -i.bak '/^[[:space:]]*Handler:/d' ${UPDATED_TEMPLATE_FILE}
sed -i.bak '/^[[:space:]]*Layers:/d' ${UPDATED_TEMPLATE_FILE}
# Remove any existing ImageUri lines so we can inject the new timestamped URI
sed -i.bak '/^[[:space:]]*ImageUri:/d' ${UPDATED_TEMPLATE_FILE}
# Remove explicit FunctionName to allow replacement without name collision
sed -i.bak '/^[[:space:]]*FunctionName:/d' ${UPDATED_TEMPLATE_FILE}

# Comment out ECRRepository resource block to avoid conflicts if repo already exists
awk '
  BEGIN {skip=0}
  /^  ECRRepository:/ {skip=1; print "# " $0; next}
  skip && /^[ ]{2}[A-Za-z]/ {skip=0}
  skip {print "# " $0; next}
  {print}
' ${UPDATED_TEMPLATE_FILE} > ${UPDATED_TEMPLATE_FILE}.tmp && mv ${UPDATED_TEMPLATE_FILE}.tmp ${UPDATED_TEMPLATE_FILE}

# Add the tagged image URI to the Lambda function properties to force update
sed -i.bak "s|PackageType: Image|PackageType: Image\\n      ImageUri: ${ECR_URI_TAGGED}|g" ${UPDATED_TEMPLATE_FILE}

# Deploy with SAM
echo "Deploying application with SAM..."

# Base parameters
PARAMS="Environment=\"${ENVIRONMENT}\" InlineRemoteImages=\"${INLINE_REMOTE_IMAGES}\""

# Add password parameter only if it's not empty
if [ -n "${PASSWORD}" ]; then
  PARAMS="${PARAMS} AppPassword=\"${PASSWORD}\""
fi

sam deploy \
  --template-file ${UPDATED_TEMPLATE_FILE} \
  --stack-name "eml-converter-${ENVIRONMENT}" \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides ${PARAMS} \
  --resolve-image-repos \
  --no-confirm-changeset \
  --region ${REGION} \
  --no-fail-on-empty-changeset

# Deploy frontend to S3
echo "Getting frontend bucket name..."
FRONTEND_BUCKET=$(aws cloudformation describe-stacks --stack-name "eml-converter-${ENVIRONMENT}" --query "Stacks[0].Outputs[?OutputKey=='FrontendBucketName'].OutputValue" --output text --region ${REGION})

if [ -n "${FRONTEND_BUCKET}" ]; then
  echo "Deploying frontend to S3 bucket: ${FRONTEND_BUCKET}"
  
  # Build React frontend
  cd "${PROJECT_ROOT}/frontend"
  npm install
  npm run build
  
  # Sync to S3
  aws s3 sync build/ "s3://${FRONTEND_BUCKET}/" --delete --region ${REGION}
  
  # Also deploy simple frontend
  aws s3 cp "${PROJECT_ROOT}/simple-frontend/index.html" "s3://${FRONTEND_BUCKET}/simple.html" --region ${REGION}
  
  # Get CloudFront distribution ID (resolve from domain)
  CF_URL=$(aws cloudformation describe-stacks --stack-name "eml-converter-${ENVIRONMENT}" --query "Stacks[0].Outputs[?OutputKey=='CloudFrontURL'].OutputValue" --output text --region ${REGION})
  CF_DOMAIN="${CF_URL#https://}"
  CLOUDFRONT_ID=$(aws cloudfront list-distributions --query "DistributionList.Items[?DomainName=='${CF_DOMAIN}'].Id | [0]" --output text 2>/dev/null || true)

  if [ -n "${CLOUDFRONT_ID}" ] && [ "${CLOUDFRONT_ID}" != "None" ]; then
    echo "Invalidating CloudFront cache for distribution: ${CLOUDFRONT_ID}"
    aws cloudfront create-invalidation --distribution-id "${CLOUDFRONT_ID}" --paths "/*"
  else
    echo "Warning: Could not resolve CloudFront distribution ID for domain ${CF_DOMAIN}. Skipping invalidation."
  fi
  
  # Display the CloudFront URL
  CLOUDFRONT_URL=$(aws cloudformation describe-stacks --stack-name "eml-converter-${ENVIRONMENT}" --query "Stacks[0].Outputs[?OutputKey=='CloudFrontURL'].OutputValue" --output text --region ${REGION})
  echo "Frontend deployed successfully to: ${CLOUDFRONT_URL}"
fi

# Cleanup
echo "Cleaning up temporary files..."
rm -f ${UPDATED_TEMPLATE_FILE} ${UPDATED_TEMPLATE_FILE}.bak

echo "Deployment completed successfully!"
echo "The application is now using a container with Playwright for PDF conversion."
