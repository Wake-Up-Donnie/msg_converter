#!/bin/bash

# CDK Deployment Script for EML Converter
# This script deploys the complete infrastructure including DynamoDB user table
# and automatically creates whitelisted users

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
ENVIRONMENT="prod"
REGION="us-east-1"
AWS_ACCOUNT_ID=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --environment|-e)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --region|-r)
            REGION="$2"
            shift 2
            ;;
        --account|-a)
            AWS_ACCOUNT_ID="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: ./deploy.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -e, --environment ENV    Environment name (dev/staging/prod) [default: prod]"
            echo "  -r, --region REGION      AWS region [default: us-east-1]"
            echo "  -a, --account ACCOUNT    AWS account ID (optional, will auto-detect)"
            echo "  -h, --help              Show this help message"
            echo ""
            echo "Examples:"
            echo "  ./deploy.sh"
            echo "  ./deploy.sh --environment staging --region us-west-2"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}EML Converter CDK Deployment${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""
echo -e "Environment: ${GREEN}$ENVIRONMENT${NC}"
echo -e "Region:      ${GREEN}$REGION${NC}"
echo ""

# Check if AWS credentials are configured
if ! aws sts get-caller-identity &>/dev/null; then
    echo -e "${RED}❌ AWS credentials not configured${NC}"
    echo "Run: aws configure"
    exit 1
fi

# Get AWS account ID if not provided
if [ -z "$AWS_ACCOUNT_ID" ]; then
    AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
    echo -e "AWS Account: ${GREEN}$AWS_ACCOUNT_ID${NC}"
fi

echo ""

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}Creating Python virtual environment...${NC}"
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies
echo -e "${YELLOW}Installing CDK dependencies...${NC}"
pip install -q -r requirements.txt

echo ""

# Bootstrap CDK (if not already done)
echo -e "${YELLOW}Checking CDK bootstrap status...${NC}"
if ! aws cloudformation describe-stacks --stack-name CDKToolkit --region $REGION &>/dev/null; then
    echo -e "${YELLOW}Bootstrapping CDK in $REGION...${NC}"
    cdk bootstrap aws://$AWS_ACCOUNT_ID/$REGION
else
    echo -e "${GREEN}✓ CDK already bootstrapped${NC}"
fi

echo ""

# Check if Docker is running (needed for Lambda container)
if ! docker info &>/dev/null; then
    echo -e "${RED}❌ Docker is not running${NC}"
    echo "Docker is required to build the Lambda container image"
    exit 1
fi

# Build and push Lambda container (if Dockerfile exists)
if [ -f "../aws/Dockerfile" ]; then
    echo -e "${YELLOW}Building Lambda container image...${NC}"

    # Get ECR repository URI (will be created if it doesn't exist)
    ECR_REPO="$AWS_ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/eml-converter-$ENVIRONMENT"

    # Create ECR repository if it doesn't exist
    if ! aws ecr describe-repositories --repository-names "eml-converter-$ENVIRONMENT" --region $REGION &>/dev/null; then
        echo -e "${YELLOW}Creating ECR repository...${NC}"
        aws ecr create-repository --repository-name "eml-converter-$ENVIRONMENT" --region $REGION
    fi

    # Login to ECR
    echo -e "${YELLOW}Logging in to ECR...${NC}"
    aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin $ECR_REPO

    # Build and push image
    echo -e "${YELLOW}Building Docker image...${NC}"
    cd ..
    docker build -t eml-converter:latest -f aws/Dockerfile .
    docker tag eml-converter:latest $ECR_REPO:latest

    echo -e "${YELLOW}Pushing to ECR...${NC}"
    docker push $ECR_REPO:latest

    cd cdk
    echo -e "${GREEN}✓ Container image pushed to ECR${NC}"
    echo ""
fi

# Show whitelisted users
echo -e "${BLUE}Whitelisted Users Configuration:${NC}"
if [ -f "whitelist_config.json" ]; then
    python3 -c "
import json
with open('whitelist_config.json', 'r') as f:
    config = json.load(f)
    emails = config.get('whitelisted_emails', [])
    print(f'  Total users to whitelist: {len(emails)}')
    for user in emails:
        if isinstance(user, dict):
            print(f'    - {user.get(\"email\")} ({user.get(\"name\", \"No name\")})')
        else:
            print(f'    - {user}')
"
else
    echo -e "${YELLOW}  No whitelist_config.json found${NC}"
fi

echo ""

# Synthesize CloudFormation template
echo -e "${YELLOW}Synthesizing CloudFormation template...${NC}"
export AWS_ACCOUNT_ID=$AWS_ACCOUNT_ID
export AWS_REGION=$REGION
export ENVIRONMENT=$ENVIRONMENT

cdk synth --context environment=$ENVIRONMENT --context region=$REGION

echo ""

# Deploy the stack
echo -e "${YELLOW}Deploying CDK stack...${NC}"
echo -e "${YELLOW}This may take 10-15 minutes...${NC}"
echo ""

cdk deploy \
    --context environment=$ENVIRONMENT \
    --context region=$REGION \
    --require-approval never \
    --outputs-file outputs.json

echo ""
echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN}✓ Deployment Complete!${NC}"
echo -e "${GREEN}======================================${NC}"
echo ""

# Display outputs
if [ -f "outputs.json" ]; then
    echo -e "${BLUE}Stack Outputs:${NC}"
    python3 -c "
import json
with open('outputs.json', 'r') as f:
    outputs = json.load(f)
    for stack_name, stack_outputs in outputs.items():
        for key, value in stack_outputs.items():
            print(f'  {key}: {value}')
"
    echo ""
fi

# Get CloudWatch Logs for user passwords
STACK_NAME="EmlConverterStack-$ENVIRONMENT"
echo -e "${BLUE}Checking for whitelisted user passwords...${NC}"
echo -e "${YELLOW}Looking in CloudWatch Logs...${NC}"
echo ""

# Find the user creator Lambda function log group
LOG_GROUP="/aws/lambda/${STACK_NAME}-UserCreatorFunction"

if aws logs describe-log-groups --log-group-name-prefix "$LOG_GROUP" --region $REGION &>/dev/null; then
    echo -e "${GREEN}✓ Found user creator logs${NC}"
    echo -e "${BLUE}Recent passwords (last 10 minutes):${NC}"
    echo ""

    # Get recent log events
    aws logs filter-log-events \
        --log-group-name "$LOG_GROUP" \
        --start-time $(($(date +%s) * 1000 - 600000)) \
        --filter-pattern "Password for" \
        --region $REGION \
        --query 'events[*].message' \
        --output text 2>/dev/null || echo "  No password logs found (users may already exist)"

    echo ""
fi

echo -e "${GREEN}Deployment successful!${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "  1. Check CloudWatch Logs above for whitelisted user passwords"
echo "  2. Deploy frontend: cd ../frontend && npm run build && aws s3 sync build/ s3://FRONTEND_BUCKET/"
echo "  3. Access the application via the CloudFront URL shown above"
echo "  4. To add more whitelisted users, edit whitelist_config.json and redeploy"
echo ""
echo -e "${BLUE}Useful commands:${NC}"
echo "  View logs: aws logs tail $LOG_GROUP --follow --region $REGION"
echo "  Update stack: ./deploy.sh"
echo "  Destroy stack: cdk destroy --context environment=$ENVIRONMENT"
echo ""
