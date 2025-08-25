#!/bin/bash
set -euo pipefail

# Helper: Fetch CloudFront and API Gateway URLs for a given environment
# Usage:
#   ./aws/get_api_urls.sh              # defaults to prod
#   ./aws/get_api_urls.sh dev          # for dev environment
#   ENVIRONMENT=staging ./aws/get_api_urls.sh
#
# Outputs exported-friendly lines you can eval:
#   export CF_URL=... ; export API_URL=...

ENVIRONMENT="${1:-${ENVIRONMENT:-prod}}"
REGION="${AWS_REGION:-us-east-1}"
STACK_NAME="eml-converter-${ENVIRONMENT}"

echo "🔍 Fetching URLs for stack: ${STACK_NAME} (region: ${REGION})"

if ! aws cloudformation describe-stacks --stack-name "${STACK_NAME}" --region "${REGION}" >/dev/null 2>&1; then
  echo "❌ Stack not found: ${STACK_NAME} (region ${REGION})" >&2
  exit 1
fi

CF_URL=$(aws cloudformation describe-stacks --stack-name "${STACK_NAME}" \
  --region "${REGION}" \
  --query "Stacks[0].Outputs[?OutputKey=='CloudFrontURL'].OutputValue" --output text)

API_URL=$(aws cloudformation describe-stacks --stack-name "${STACK_NAME}" \
  --region "${REGION}" \
  --query "Stacks[0].Outputs[?OutputKey=='APIGatewayURL'].OutputValue" --output text)

if [ -z "${CF_URL}" ] || [ "${CF_URL}" == "None" ]; then
  echo "⚠️  CloudFront URL not found in stack outputs" >&2
else
  echo "CloudFront URL: ${CF_URL}"
fi

if [ -z "${API_URL}" ] || [ "${API_URL}" == "None" ]; then
  echo "⚠️  API Gateway URL not found in stack outputs" >&2
else
  echo "API Gateway URL: ${API_URL}"
fi

echo ""
if [ -n "${CF_URL}" ] && [ "${CF_URL}" != "None" ]; then
  echo "To use with convert_single_eml.sh (CloudFront):"
  echo "  ./convert_single_eml.sh \"test_eml/FW_ Starlight Comment from JCSG.eml\" \"${APP_PASSWORD:-mysecretpassword}\" ${CF_URL}/api"
fi
if [ -n "${API_URL}" ] && [ "${API_URL}" != "None" ]; then
  echo "To use with convert_single_eml.sh (API Gateway stage):"
  echo "  ./convert_single_eml.sh \"test_eml/FW_ Starlight Comment from JCSG.eml\" \"${APP_PASSWORD:-mysecretpassword}\" ${API_URL}"
fi

echo ""
echo "Export variables for convenience:"
echo "  export CF_API_BASE=${CF_URL}/api"
echo "  export APIGW_API_BASE=${API_URL}"

echo "Done."