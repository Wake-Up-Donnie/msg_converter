#!/bin/bash

###############################################################################
# Subscription Landing Page Deployment Script
# Deploys the Stripe-integrated subscription landing page to AWS
###############################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
ENVIRONMENT="dev"
REGION="us-east-1"
SKIP_STRIPE_SETUP=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --env)
      ENVIRONMENT="$2"
      shift 2
      ;;
    --region)
      REGION="$2"
      shift 2
      ;;
    --skip-stripe-setup)
      SKIP_STRIPE_SETUP=true
      shift
      ;;
    --help)
      echo "Usage: $0 [options]"
      echo ""
      echo "Options:"
      echo "  --env ENV              Environment (dev or prod, default: dev)"
      echo "  --region REGION        AWS region (default: us-east-1)"
      echo "  --skip-stripe-setup    Skip Stripe product setup"
      echo "  --help                 Show this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      echo "Use --help for usage information"
      exit 1
      ;;
  esac
done

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}  Subscription Landing Page Deployment${NC}"
echo -e "${BLUE}  Environment: ${ENVIRONMENT}${NC}"
echo -e "${BLUE}  Region: ${REGION}${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

# Check prerequisites
echo -e "${YELLOW}Checking prerequisites...${NC}"

if ! command -v aws &> /dev/null; then
    echo -e "${RED}Error: AWS CLI not found. Please install it first.${NC}"
    exit 1
fi

if ! command -v sam &> /dev/null; then
    echo -e "${RED}Error: AWS SAM CLI not found. Please install it first.${NC}"
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 not found. Please install it first.${NC}"
    exit 1
fi

if ! command -v node &> /dev/null; then
    echo -e "${RED}Error: Node.js not found. Please install it first.${NC}"
    exit 1
fi

echo -e "${GREEN}✓ All prerequisites met${NC}"
echo ""

# Step 1: Setup Stripe products (if not skipped)
if [ "$SKIP_STRIPE_SETUP" = false ]; then
    echo -e "${YELLOW}Step 1: Setting up Stripe products...${NC}"
    cd stripe-setup

    # Install stripe package if not present
    if ! pip3 show stripe &> /dev/null; then
        pip3 install stripe
    fi

    python3 setup_stripe_products.py

    if [ ! -f "stripe_config.json" ]; then
        echo -e "${RED}Error: Stripe configuration not found. Please run setup_stripe_products.py first.${NC}"
        exit 1
    fi

    cd ..
    echo -e "${GREEN}✓ Stripe products configured${NC}"
    echo ""
else
    echo -e "${YELLOW}Skipping Stripe setup (--skip-stripe-setup flag set)${NC}"
    echo ""
fi

# Load Stripe configuration
if [ -f "stripe-setup/stripe_config.json" ]; then
    MONTHLY_PRICE_ID=$(python3 -c "import json; print(json.load(open('stripe-setup/stripe_config.json'))['monthly_price_id'])")
    YEARLY_PRICE_ID=$(python3 -c "import json; print(json.load(open('stripe-setup/stripe_config.json'))['yearly_price_id'])")
    STRIPE_PUBLISHABLE_KEY=$(python3 -c "import json; print(json.load(open('stripe-setup/stripe_config.json'))['publishable_key'])")
else
    echo -e "${RED}Error: stripe_config.json not found. Run without --skip-stripe-setup first.${NC}"
    exit 1
fi

# Stripe keys from environment or prompt
if [ -z "$STRIPE_SECRET_KEY" ]; then
    echo -e "${YELLOW}Enter your Stripe secret key:${NC}"
    read -s STRIPE_SECRET_KEY
    echo ""
fi

# JWT secret key
JWT_SECRET_KEY=$(openssl rand -base64 32)

# Step 2: Deploy backend (SAM)
echo -e "${YELLOW}Step 2: Deploying backend infrastructure...${NC}"

STACK_NAME="subscription-landing-${ENVIRONMENT}"

sam build \
    --template-file aws/template-landing-page.yaml \
    --region ${REGION}

sam deploy \
    --template-file aws/template-landing-page.yaml \
    --stack-name ${STACK_NAME} \
    --parameter-overrides \
        Environment=${ENVIRONMENT} \
        StripeSecretKey="${STRIPE_SECRET_KEY}" \
        StripePublishableKey="${STRIPE_PUBLISHABLE_KEY}" \
        MonthlyPriceId="${MONTHLY_PRICE_ID}" \
        YearlyPriceId="${YEARLY_PRICE_ID}" \
        JWTSecretKey="${JWT_SECRET_KEY}" \
    --capabilities CAPABILITY_IAM \
    --region ${REGION} \
    --resolve-s3 \
    --no-fail-on-empty-changeset

echo -e "${GREEN}✓ Backend deployed${NC}"
echo ""

# Step 3: Get stack outputs
echo -e "${YELLOW}Step 3: Retrieving deployment information...${NC}"

API_URL=$(aws cloudformation describe-stacks \
    --stack-name ${STACK_NAME} \
    --region ${REGION} \
    --query 'Stacks[0].Outputs[?OutputKey==`APIGatewayURL`].OutputValue' \
    --output text)

FRONTEND_BUCKET=$(aws cloudformation describe-stacks \
    --stack-name ${STACK_NAME} \
    --region ${REGION} \
    --query 'Stacks[0].Outputs[?OutputKey==`FrontendBucketName`].OutputValue' \
    --output text)

CLOUDFRONT_URL=$(aws cloudformation describe-stacks \
    --stack-name ${STACK_NAME} \
    --region ${REGION} \
    --query 'Stacks[0].Outputs[?OutputKey==`CloudFrontURL`].OutputValue' \
    --output text)

CLOUDFRONT_DIST_ID=$(aws cloudformation describe-stacks \
    --stack-name ${STACK_NAME} \
    --region ${REGION} \
    --query 'Stacks[0].Outputs[?OutputKey==`CloudFrontDistributionId`].OutputValue' \
    --output text)

WEBHOOK_URL=$(aws cloudformation describe-stacks \
    --stack-name ${STACK_NAME} \
    --region ${REGION} \
    --query 'Stacks[0].Outputs[?OutputKey==`WebhookURL`].OutputValue' \
    --output text)

echo -e "${GREEN}✓ Stack outputs retrieved${NC}"
echo ""

# Step 3.5: Update Lambda functions with CloudFront URL
echo -e "${YELLOW}Step 3.5: Updating Lambda functions with CloudFront URL...${NC}"

aws lambda update-function-configuration \
    --function-name "landing-checkout-${ENVIRONMENT}" \
    --environment "Variables={ENVIRONMENT=${ENVIRONMENT},USERS_TABLE=subscription-users-${ENVIRONMENT},STRIPE_SECRET_KEY=${STRIPE_SECRET_KEY},MONTHLY_PRICE_ID=${MONTHLY_PRICE_ID},YEARLY_PRICE_ID=${YEARLY_PRICE_ID},SECRET_KEY=${JWT_SECRET_KEY},FRONTEND_URL=${CLOUDFRONT_URL}}" \
    --region ${REGION} > /dev/null

aws lambda update-function-configuration \
    --function-name "landing-portal-${ENVIRONMENT}" \
    --environment "Variables={ENVIRONMENT=${ENVIRONMENT},USERS_TABLE=subscription-users-${ENVIRONMENT},STRIPE_SECRET_KEY=${STRIPE_SECRET_KEY},MONTHLY_PRICE_ID=${MONTHLY_PRICE_ID},YEARLY_PRICE_ID=${YEARLY_PRICE_ID},SECRET_KEY=${JWT_SECRET_KEY},FRONTEND_URL=${CLOUDFRONT_URL}}" \
    --region ${REGION} > /dev/null

echo -e "${GREEN}✓ Lambda functions updated${NC}"
echo ""

# Step 4: Build and deploy frontend
echo -e "${YELLOW}Step 4: Building and deploying frontend...${NC}"

cd landing-frontend

# Install dependencies
if [ ! -d "node_modules" ]; then
    npm install
fi

# Build with environment variables
REACT_APP_API_URL="${API_URL}" \
REACT_APP_STRIPE_PUBLISHABLE_KEY="${STRIPE_PUBLISHABLE_KEY}" \
npm run build

# Deploy to S3
aws s3 sync build/ s3://${FRONTEND_BUCKET}/ --delete --region ${REGION}

# Invalidate CloudFront cache
aws cloudfront create-invalidation \
    --distribution-id ${CLOUDFRONT_DIST_ID} \
    --paths "/*" \
    --region ${REGION} > /dev/null

cd ..

echo -e "${GREEN}✓ Frontend deployed${NC}"
echo ""

# Step 5: Display deployment information
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}  Deployment Complete!${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""
echo -e "${BLUE}Frontend URL:${NC} ${CLOUDFRONT_URL}"
echo -e "${BLUE}API URL:${NC} ${API_URL}"
echo ""
echo -e "${YELLOW}⚠️  IMPORTANT: Configure Stripe Webhook${NC}"
echo -e "   1. Go to: https://dashboard.stripe.com/webhooks"
echo -e "   2. Click 'Add endpoint'"
echo -e "   3. Enter URL: ${WEBHOOK_URL}"
echo -e "   4. Select events:"
echo -e "      - checkout.session.completed"
echo -e "      - customer.subscription.created"
echo -e "      - customer.subscription.updated"
echo -e "      - customer.subscription.deleted"
echo -e "      - invoice.payment_succeeded"
echo -e "      - invoice.payment_failed"
echo -e "   5. Copy the webhook signing secret"
echo -e "   6. Update the stack with the webhook secret:"
echo ""
echo -e "   ${BLUE}sam deploy \\${NC}"
echo -e "   ${BLUE}  --template-file aws/template-landing-page.yaml \\${NC}"
echo -e "   ${BLUE}  --stack-name ${STACK_NAME} \\${NC}"
echo -e "   ${BLUE}  --parameter-overrides StripeWebhookSecret=whsec_xxx \\${NC}"
echo -e "   ${BLUE}  --capabilities CAPABILITY_IAM --no-confirm-changeset${NC}"
echo ""
echo -e "${GREEN}================================================${NC}"

# Save deployment info
cat > deployment-info-${ENVIRONMENT}.txt << EOF
Deployment Information - ${ENVIRONMENT}
Generated: $(date)

Frontend URL: ${CLOUDFRONT_URL}
API URL: ${API_URL}
Webhook URL: ${WEBHOOK_URL}
Frontend Bucket: ${FRONTEND_BUCKET}
CloudFront Distribution ID: ${CLOUDFRONT_DIST_ID}
Stack Name: ${STACK_NAME}
Region: ${REGION}

Next Steps:
1. Configure Stripe webhook at: https://dashboard.stripe.com/webhooks
2. Test the application at: ${CLOUDFRONT_URL}
3. Register a test user and try the subscription flow
EOF

echo -e "${GREEN}✓ Deployment information saved to: deployment-info-${ENVIRONMENT}.txt${NC}"
echo ""
