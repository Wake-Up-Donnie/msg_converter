#!/bin/bash

# Unified Deployment Script for EML Converter
# Deploys infrastructure AND automatically creates whitelisted users
#
# Usage: ./deploy.sh [ENVIRONMENT] [REGION] [PASSWORD]
#
# Arguments:
#   ENVIRONMENT  - Environment name (dev/staging/prod) [default: dev]
#   REGION       - AWS region [default: us-east-1]
#   PASSWORD     - Optional app password for basic auth [default: none]
#
# Examples:
#   ./deploy.sh dev us-east-1 "mysecretpassword"
#   ./deploy.sh prod us-east-1
#   ./deploy.sh staging us-west-2

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Parse arguments (positional for backwards compatibility)
ENVIRONMENT="${1:-dev}"
REGION="${2:-us-east-1}"
PASSWORD="${3:-}"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  EML Converter Deployment${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "Environment: ${GREEN}${ENVIRONMENT}${NC}"
echo -e "Region:      ${GREEN}${REGION}${NC}"
echo -e "Password:    ${GREEN}${PASSWORD:+***set***}${PASSWORD:-not set}${NC}"
echo ""

# Check if AWS credentials are configured
if ! aws sts get-caller-identity &>/dev/null; then
    echo -e "${RED}❌ AWS credentials not configured${NC}"
    echo "Run: aws configure"
    exit 1
fi

AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo -e "AWS Account: ${GREEN}${AWS_ACCOUNT_ID}${NC}"
echo ""

# Step 1: Deploy infrastructure using existing script
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}Step 1: Deploying Infrastructure${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

DEPLOY_ARGS="--env ${ENVIRONMENT} --region ${REGION}"
if [ -n "${PASSWORD}" ]; then
    DEPLOY_ARGS="${DEPLOY_ARGS} --password ${PASSWORD}"
fi

echo -e "${YELLOW}Running: aws/deploy-container.sh ${DEPLOY_ARGS}${NC}"
echo ""

"${SCRIPT_DIR}/aws/deploy-container.sh" ${DEPLOY_ARGS}

echo ""
echo -e "${GREEN}✓ Infrastructure deployment complete${NC}"
echo ""

# Step 2: Create whitelisted users in DynamoDB
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}Step 2: Creating Whitelisted Users${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Check if whitelist config exists
WHITELIST_CONFIG="${SCRIPT_DIR}/cdk/whitelist_config.json"

if [ ! -f "${WHITELIST_CONFIG}" ]; then
    echo -e "${YELLOW}⚠ No whitelist configuration found at ${WHITELIST_CONFIG}${NC}"
    echo -e "${YELLOW}Skipping user creation.${NC}"
    echo ""
    echo -e "${BLUE}To add whitelisted users:${NC}"
    echo "  1. cd cdk"
    echo "  2. python3 add_to_whitelist.py --email user@example.com --name \"User Name\""
    echo "  3. Run ./deploy.sh again"
    echo ""
else
    # Check if Python 3 is available
    if ! command -v python3 &>/dev/null; then
        echo -e "${RED}❌ Python 3 not found${NC}"
        echo "Python 3 is required to create whitelisted users"
        exit 1
    fi

    # Check if boto3 and werkzeug are installed
    if ! python3 -c "import boto3, werkzeug" 2>/dev/null; then
        echo -e "${YELLOW}Installing required Python packages...${NC}"
        pip3 install -q boto3 werkzeug || {
            echo -e "${RED}❌ Failed to install required packages${NC}"
            echo "Run: pip3 install boto3 werkzeug"
            exit 1
        }
    fi

    # Get whitelisted emails from config
    WHITELISTED_EMAILS=$(python3 -c "
import json
import sys

try:
    with open('${WHITELIST_CONFIG}', 'r') as f:
        config = json.load(f)
        emails = config.get('whitelisted_emails', [])
        if not emails:
            sys.exit(1)
        print(len(emails))
        for user in emails:
            if isinstance(user, dict):
                print(user.get('email', ''))
            else:
                print(user)
except Exception as e:
    print(f'Error: {e}', file=sys.stderr)
    sys.exit(1)
" 2>/dev/null)

    if [ $? -ne 0 ] || [ -z "${WHITELISTED_EMAILS}" ]; then
        echo -e "${YELLOW}⚠ No whitelisted users found in configuration${NC}"
        echo "Add users with: cd cdk && python3 add_to_whitelist.py --email user@example.com"
        echo ""
    else
        # Parse the output
        NUM_USERS=$(echo "${WHITELISTED_EMAILS}" | head -n 1)
        echo -e "${BLUE}Found ${NUM_USERS} whitelisted user(s) in configuration${NC}"
        echo ""

        # Create each user
        echo "${WHITELISTED_EMAILS}" | tail -n +2 | while read -r EMAIL; do
            if [ -n "${EMAIL}" ]; then
                echo -e "${YELLOW}Creating user: ${EMAIL}${NC}"

                # Run the add_user_to_dynamodb.py script
                python3 "${SCRIPT_DIR}/backend/add_user_to_dynamodb.py" \
                    --email "${EMAIL}" \
                    --environment "${ENVIRONMENT}" \
                    --region "${REGION}" 2>&1 | tee /tmp/user_creation_${ENVIRONMENT}.log

                # Check if creation was successful
                if grep -q "✅ User created successfully" /tmp/user_creation_${ENVIRONMENT}.log; then
                    # Extract and save password
                    PASSWORD_LINE=$(grep "Password:" /tmp/user_creation_${ENVIRONMENT}.log | tail -1)
                    if [ -n "${PASSWORD_LINE}" ]; then
                        echo -e "${GREEN}✓ User created: ${EMAIL}${NC}"
                        echo "${PASSWORD_LINE}" >> "${SCRIPT_DIR}/whitelisted_users_credentials_${ENVIRONMENT}.txt"
                    fi
                elif grep -q "already exists" /tmp/user_creation_${ENVIRONMENT}.log; then
                    echo -e "${GREEN}✓ User already exists: ${EMAIL}${NC}"
                else
                    echo -e "${YELLOW}⚠ Could not create user: ${EMAIL}${NC}"
                fi

                echo ""
            fi
        done

        # Display credentials file location
        if [ -f "${SCRIPT_DIR}/whitelisted_users_credentials_${ENVIRONMENT}.txt" ]; then
            echo ""
            echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo -e "${GREEN}Whitelisted User Credentials${NC}"
            echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo ""
            cat "${SCRIPT_DIR}/whitelisted_users_credentials_${ENVIRONMENT}.txt"
            echo ""
            echo -e "${YELLOW}⚠ IMPORTANT: Save these passwords securely!${NC}"
            echo -e "Credentials saved to: ${SCRIPT_DIR}/whitelisted_users_credentials_${ENVIRONMENT}.txt"
            echo ""
        fi
    fi
fi

# Step 3: Display deployment summary
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}Deployment Summary${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Get stack outputs
echo -e "${BLUE}Stack Outputs:${NC}"
aws cloudformation describe-stacks \
    --stack-name "eml-converter-${ENVIRONMENT}" \
    --region "${REGION}" \
    --query 'Stacks[0].Outputs[*].[OutputKey,OutputValue]' \
    --output table 2>/dev/null || echo "  (Could not retrieve stack outputs)"

echo ""

# Get CloudFront URL
CLOUDFRONT_URL=$(aws cloudformation describe-stacks \
    --stack-name "eml-converter-${ENVIRONMENT}" \
    --query "Stacks[0].Outputs[?OutputKey=='CloudFrontURL'].OutputValue" \
    --output text \
    --region "${REGION}" 2>/dev/null || echo "")

if [ -n "${CLOUDFRONT_URL}" ]; then
    echo -e "${GREEN}✓ Application URL: ${CLOUDFRONT_URL}${NC}"
fi

# Get Users Table
USERS_TABLE=$(aws cloudformation describe-stacks \
    --stack-name "eml-converter-${ENVIRONMENT}" \
    --query "Stacks[0].Outputs[?OutputKey=='UsersTableName'].OutputValue" \
    --output text \
    --region "${REGION}" 2>/dev/null || echo "")

if [ -n "${USERS_TABLE}" ]; then
    echo -e "${GREEN}✓ Users Table: ${USERS_TABLE}${NC}"

    # Count users in DynamoDB
    USER_COUNT=$(aws dynamodb scan \
        --table-name "${USERS_TABLE}" \
        --select COUNT \
        --region "${REGION}" \
        --query 'Count' \
        --output text 2>/dev/null || echo "0")

    echo -e "${GREEN}✓ Total Users: ${USER_COUNT}${NC}"

    # Count unlimited users
    UNLIMITED_COUNT=$(aws dynamodb scan \
        --table-name "${USERS_TABLE}" \
        --filter-expression "is_unlimited = :true" \
        --expression-attribute-values '{":true": {"BOOL": true}}' \
        --select COUNT \
        --region "${REGION}" \
        --query 'Count' \
        --output text 2>/dev/null || echo "0")

    echo -e "${GREEN}✓ Whitelisted Users (Unlimited): ${UNLIMITED_COUNT}${NC}"
fi

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✓ Deployment Complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo -e "${BLUE}Next Steps:${NC}"
echo "  1. Share whitelisted user credentials securely"
echo "  2. Test the application: ${CLOUDFRONT_URL}"
echo "  3. Users can log in with unlimited access"
echo ""

echo -e "${BLUE}Useful Commands:${NC}"
echo "  # Add more whitelisted users"
echo "  cd cdk && python3 add_to_whitelist.py --email newuser@example.com"
echo ""
echo "  # Redeploy with new users"
echo "  ./deploy.sh ${ENVIRONMENT} ${REGION} ${PASSWORD:+\"***\"}"
echo ""
echo "  # View DynamoDB users"
echo "  aws dynamodb scan --table-name ${USERS_TABLE} --region ${REGION}"
echo ""
echo "  # Verify a specific user"
echo "  python3 backend/add_user_to_dynamodb.py --email USER@EMAIL --verify --environment ${ENVIRONMENT} --region ${REGION}"
echo ""

# Cleanup temp files
rm -f /tmp/user_creation_*.log

echo -e "${GREEN}Deployment script completed successfully!${NC}"
