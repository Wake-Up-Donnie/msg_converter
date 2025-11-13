# DynamoDB User Management Setup Guide

This guide explains how to set up DynamoDB for user management and add users with free unlimited access to the EML/MSG converter application.

## Overview

The application now supports two database backends:
- **SQLite** (local development)
- **DynamoDB** (AWS production deployment)

The application automatically detects which to use based on environment variables.

---

## Step 1: Deploy the DynamoDB Table

The DynamoDB table is defined in the SAM template and will be created automatically when you deploy the stack.

### Deploy the Stack

```bash
# Navigate to your project
cd /home/user/msg_converter

# Build and deploy using SAM
sam build -t aws/template.yaml

sam deploy \
  --template-file aws/template.yaml \
  --stack-name eml-converter-prod \
  --parameter-overrides \
      Environment=prod \
      AppPassword="" \
  --capabilities CAPABILITY_IAM \
  --region us-east-1
```

### Verify Table Creation

After deployment, verify the table was created:

```bash
aws dynamodb describe-table \
  --table-name eml-converter-users-prod \
  --region us-east-1
```

You should see output showing the table status as `ACTIVE`.

---

## Step 2: Add User to DynamoDB

Once the table is deployed, you can add users with free unlimited access.

### Method 1: Using the Python Script (Recommended)

```bash
cd /home/user/msg_converter/backend

# Add user with free unlimited access
python3 add_user_to_dynamodb.py \
  --email tbobik91@gmail.com \
  --environment prod \
  --region us-east-1

# Output will show:
# ✅ User created successfully in DynamoDB!
#    Email: tbobik91@gmail.com
#    Password: <randomly-generated-password>
#    Subscription Status: active
#    Unlimited Access: Yes (Free Forever)
```

**Save the password!** It will be shown only once.

### Method 2: Specify Custom Password

```bash
python3 add_user_to_dynamodb.py \
  --email tbobik91@gmail.com \
  --password "MySecurePassword123!" \
  --environment prod \
  --region us-east-1
```

### Method 3: Using AWS CLI Directly

If you prefer to use the AWS CLI:

```bash
aws dynamodb put-item \
  --table-name eml-converter-users-prod \
  --item '{
    "email": {"S": "tbobik91@gmail.com"},
    "user_id": {"S": "'"$(uuidgen)"'"},
    "password_hash": {"S": "<bcrypt-hashed-password>"},
    "subscription_status": {"S": "active"},
    "is_unlimited": {"BOOL": true},
    "free_conversions_used": {"N": "0"},
    "created_at": {"S": "'"$(date -u +"%Y-%m-%dT%H:%M:%SZ")"'"},
    "updated_at": {"S": "'"$(date -u +"%Y-%m-%dT%H:%M:%SZ")"'"}
  }' \
  --region us-east-1
```

Note: You'll need to hash the password using bcrypt before adding it this way.

---

## Step 3: Verify User Creation

### Verify in DynamoDB

```bash
python3 add_user_to_dynamodb.py \
  --email tbobik91@gmail.com \
  --verify \
  --environment prod \
  --region us-east-1
```

Output:
```
✅ User found in DynamoDB:
   User ID: <uuid>
   Email: tbobik91@gmail.com
   Subscription Status: active
   Unlimited Access: True
   Free Conversions Used: 0
   Created At: 2025-11-13T...
```

### Query Directly with AWS CLI

```bash
aws dynamodb get-item \
  --table-name eml-converter-users-prod \
  --key '{"email": {"S": "tbobik91@gmail.com"}}' \
  --region us-east-1
```

---

## Step 4: Test Login

Once the user is created, test logging in through the application.

### Using the API

```bash
# Get the API endpoint from CloudFormation outputs
API_URL=$(aws cloudformation describe-stacks \
  --stack-name eml-converter-prod \
  --query 'Stacks[0].Outputs[?OutputKey==`APIGatewayURL`].OutputValue' \
  --output text \
  --region us-east-1)

# Login to get JWT token
curl -X POST "$API_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "tbobik91@gmail.com",
    "password": "<password-from-step-2>"
  }'
```

Expected response:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "email": "tbobik91@gmail.com",
    "subscription_status": "active",
    "is_unlimited": true
  }
}
```

### Using the Frontend

1. Navigate to your CloudFront URL
2. Click "Login"
3. Enter `tbobik91@gmail.com` and the password
4. You should be logged in with unlimited access

---

## DynamoDB Table Schema

The `eml-converter-users-{environment}` table has the following schema:

### Primary Key
- **email** (String, HASH) - User's email address

### Attributes
| Attribute | Type | Description |
|-----------|------|-------------|
| `email` | String | User's email (primary key) |
| `user_id` | String | Unique user identifier (UUID) |
| `password_hash` | String | Bcrypt hashed password |
| `subscription_status` | String | Subscription status (active, inactive, cancelled, etc.) |
| `is_unlimited` | Boolean | Whether user has unlimited access |
| `free_conversions_used` | Number | Count of free conversions used |
| `stripe_customer_id` | String | Stripe customer ID (optional) |
| `stripe_subscription_id` | String | Stripe subscription ID (optional) |
| `created_at` | String | ISO 8601 timestamp of creation |
| `updated_at` | String | ISO 8601 timestamp of last update |

### Global Secondary Index
- **UserIdIndex** - Allows querying by `user_id`

### Features
- **Billing Mode:** Pay-per-request (on-demand)
- **Encryption:** Server-side encryption enabled (SSE)
- **Point-in-Time Recovery:** Enabled for data protection
- **Streams:** Enabled for change tracking

---

## Application Configuration

The application automatically detects which database to use:

### Local Development (SQLite)
When these conditions are met:
- No `USERS_TABLE` environment variable
- No `AWS_EXECUTION_ENV` environment variable

The application uses SQLite (`msg_converter.db`)

### AWS Lambda (DynamoDB)
When these conditions are met:
- `USERS_TABLE` environment variable is set (automatically by SAM template)
- Running in AWS Lambda environment

The application uses DynamoDB

### Environment Variables (Set by SAM Template)
```bash
USERS_TABLE=eml-converter-users-prod
AWS_REGION_NAME=us-east-1
```

---

## Managing Users

### Add Additional Free Users

```bash
python3 add_user_to_dynamodb.py \
  --email another-user@example.com \
  --environment prod
```

### Update User Subscription

```python
from models_dynamodb import update_user_subscription

# Activate subscription
update_user_subscription(
    email="tbobik91@gmail.com",
    subscription_status="active",
    is_unlimited=True,
    stripe_customer_id="cus_xxxxx",
    stripe_subscription_id="sub_xxxxx"
)
```

### Check Conversion Limits

```python
from models_dynamodb import can_user_convert

can_convert, reason = can_user_convert("tbobik91@gmail.com")
if can_convert:
    print(f"User can convert: {reason}")
else:
    print(f"User cannot convert: {reason}")
```

### Increment Conversion Count

```python
from models_dynamodb import increment_conversion_count

# After successful conversion
increment_conversion_count("tbobik91@gmail.com")
```

---

## AWS Credentials Setup

To run the scripts locally, you need AWS credentials configured:

### Option 1: AWS CLI Configuration
```bash
aws configure
# Enter your AWS Access Key ID
# Enter your AWS Secret Access Key
# Default region: us-east-1
# Default output format: json
```

### Option 2: Environment Variables
```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-1
```

### Option 3: IAM Role (if running on EC2/Lambda)
AWS credentials are automatically available from the instance metadata service.

---

## Required IAM Permissions

The user/role running the scripts needs these DynamoDB permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:Query",
        "dynamodb:Scan",
        "dynamodb:DescribeTable"
      ],
      "Resource": [
        "arn:aws:dynamodb:us-east-1:*:table/eml-converter-users-*",
        "arn:aws:dynamodb:us-east-1:*:table/eml-converter-users-*/index/*"
      ]
    }
  ]
}
```

---

## Troubleshooting

### Error: "Unable to locate credentials"
**Problem:** AWS credentials not configured

**Solution:**
```bash
aws configure
# Or set environment variables:
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
```

### Error: "Requested resource not found"
**Problem:** DynamoDB table doesn't exist

**Solution:** Deploy the SAM template first:
```bash
sam build -t aws/template.yaml
sam deploy --stack-name eml-converter-prod --capabilities CAPABILITY_IAM
```

### Error: "User already exists"
**Problem:** Trying to create duplicate user

**Solution:** Use `--verify` flag to check existing user, or delete first:
```bash
aws dynamodb delete-item \
  --table-name eml-converter-users-prod \
  --key '{"email": {"S": "tbobik91@gmail.com"}}' \
  --region us-east-1
```

### Error: "ConditionalCheckFailedException"
**Problem:** User with that email already exists

**Solution:** Verify the existing user or use a different email

### Table Not Showing in AWS Console
**Problem:** Wrong region selected

**Solution:** Make sure you're looking in `us-east-1` (or your deployed region)

---

## Cost Estimation

### DynamoDB Costs (Pay-per-request)

| Operation | Cost per Million Requests |
|-----------|---------------------------|
| Write | $1.25 |
| Read | $0.25 |

**Example Monthly Cost:**
- 1,000 new users/month: ~$0.00125
- 10,000 logins/month: ~$0.0025
- Total: **~$0.01/month** for moderate usage

Plus data storage: **$0.25 per GB/month**

**Expected cost for small to medium usage: $0.10 - $1.00/month**

---

## Summary

✅ **Deployment Steps:**
1. Deploy SAM template with DynamoDB table
2. Run `add_user_to_dynamodb.py` to create user
3. Save the generated password
4. Verify user creation
5. Test login through API or frontend

✅ **Free User Created:**
- Email: `tbobik91@gmail.com`
- Access: Unlimited conversions (Free Forever)
- Subscription: Active
- Database: DynamoDB (persists across Lambda invocations)

✅ **Files Created:**
- `aws/template.yaml` - Updated with DynamoDB table definition
- `backend/models_dynamodb.py` - DynamoDB user management
- `backend/models_auto.py` - Auto-selecting database backend
- `backend/add_user_to_dynamodb.py` - Script to add users

---

*Last updated: 2025-11-13*
