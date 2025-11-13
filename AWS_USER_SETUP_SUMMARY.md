# AWS DynamoDB User Management - Setup Summary

## What Was Done

This update adds persistent user management using **AWS DynamoDB** so that users with free unlimited access can be stored in the cloud and persist across Lambda deployments.

---

## Changes Made

### 1. AWS Infrastructure (SAM Template)

**File:** `aws/template.yaml`

Added:
- **DynamoDB Table** (`UsersTable`) for user management
  - Table Name: `eml-converter-users-{environment}`
  - Primary Key: `email` (String)
  - Global Secondary Index: `UserIdIndex` for querying by `user_id`
  - Billing: Pay-per-request (on-demand pricing)
  - Features: Encryption, Point-in-Time Recovery, Streams

- **Lambda Permissions** - Added `DynamoDBCrudPolicy` to Lambda function

- **Environment Variables** for Lambda:
  - `USERS_TABLE`: References the DynamoDB table name
  - `AWS_REGION_NAME`: AWS region

- **CloudFormation Outputs** - Added `UsersTableName` output

### 2. Backend Code

**Files Created:**

#### `backend/models_dynamodb.py`
- Full DynamoDB implementation of user management
- Functions:
  - `get_user_by_email(email)` - Retrieve user by email
  - `get_user_by_id(user_id)` - Retrieve user by UUID
  - `create_user(email, password_hash)` - Create new user
  - `update_user_subscription(...)` - Update subscription status
  - `increment_conversion_count(email)` - Track usage
  - `can_user_convert(email, free_limit)` - Check conversion eligibility
  - `seed_unlimited_user()` - Create default unlimited user

#### `backend/models_auto.py`
- **Auto-detection** of database backend
- Uses DynamoDB when `USERS_TABLE` env var is set (AWS Lambda)
- Uses SQLite when running locally (development)
- Same interface for both backends - no code changes needed

#### `backend/add_user_to_dynamodb.py`
- Command-line script to add users to DynamoDB
- Features:
  - Create users with free unlimited access
  - Generate random passwords or use custom passwords
  - Verify existing users
  - Support for multiple environments (dev, staging, prod)

### 3. Documentation

**Files Created:**

#### `DYNAMODB_USER_SETUP.md`
Complete guide including:
- Step-by-step deployment instructions
- How to add users to DynamoDB
- Verification procedures
- Testing login functionality
- Troubleshooting guide
- Cost estimation

#### `AWS_USER_SETUP_SUMMARY.md` (this file)
Quick reference and summary of changes

---

## How to Deploy

### Step 1: Deploy the SAM Template

```bash
cd /home/user/msg_converter

sam build -t aws/template.yaml

sam deploy \
  --template-file aws/template.yaml \
  --stack-name eml-converter-prod \
  --parameter-overrides Environment=prod \
  --capabilities CAPABILITY_IAM \
  --region us-east-1
```

This creates:
- DynamoDB table: `eml-converter-users-prod`
- Lambda function with DynamoDB permissions
- API Gateway endpoints
- S3 buckets
- CloudFront distribution

### Step 2: Add User to DynamoDB

```bash
cd backend

python3 add_user_to_dynamodb.py \
  --email tbobik91@gmail.com \
  --environment prod \
  --region us-east-1
```

**Output:**
```
✅ User created successfully in DynamoDB!
   Email: tbobik91@gmail.com
   Password: <randomly-generated-password>
   Subscription Status: active
   Unlimited Access: Yes (Free Forever)
```

**Save the password!** It's shown only once.

### Step 3: Verify

```bash
python3 add_user_to_dynamodb.py \
  --email tbobik91@gmail.com \
  --verify \
  --environment prod
```

---

## User Details

### Whitelisted User for Free Access

**Email:** `tbobik91@gmail.com`

**Properties:**
- ✅ **Unlimited Access** - No conversion limits
- ✅ **Active Subscription** - Full feature access
- ✅ **Free Forever** - No expiration, no billing
- ✅ **Persistent Storage** - Stored in DynamoDB (survives Lambda restarts)

**Database Location:**
- Table: `eml-converter-users-prod` (DynamoDB)
- Region: `us-east-1`
- Access: Via Lambda with IAM permissions

---

## How It Works

### Local Development
```
User Request → Flask App → models_auto.py → models.py → SQLite (msg_converter.db)
```

### AWS Production
```
User Request → API Gateway → Lambda → models_auto.py → models_dynamodb.py → DynamoDB
```

The application **automatically detects** which database to use based on environment variables.

---

## File Structure

```
msg_converter/
├── aws/
│   └── template.yaml ........................... Updated with DynamoDB table
├── backend/
│   ├── models.py ................................ Original SQLite implementation
│   ├── models_dynamodb.py ....................... New DynamoDB implementation
│   ├── models_auto.py ........................... Auto-selecting database wrapper
│   ├── add_user_to_dynamodb.py .................. Script to add users
│   ├── create_free_user.py ...................... Script for SQLite (local)
│   └── requirements.txt ......................... Already includes boto3
├── DYNAMODB_USER_SETUP.md ....................... Complete setup guide
├── AWS_USER_SETUP_SUMMARY.md .................... This summary
└── FREE_USER_CREDENTIALS.md ..................... Local SQLite user credentials
```

---

## Next Steps

### To Use the Free User Account

1. **Deploy the stack** (see Step 1 above)
2. **Add the user** to DynamoDB (see Step 2 above)
3. **Get the CloudFront URL** from stack outputs:
   ```bash
   aws cloudformation describe-stacks \
     --stack-name eml-converter-prod \
     --query 'Stacks[0].Outputs[?OutputKey==`CloudFrontURL`].OutputValue' \
     --output text
   ```
4. **Navigate to the URL** and log in with `tbobik91@gmail.com` and the password
5. **Start converting** emails with unlimited access!

### To Add More Free Users

```bash
python3 backend/add_user_to_dynamodb.py \
  --email another-user@example.com \
  --environment prod
```

---

## Testing Without Deployment

For local testing (without deploying to AWS):

```bash
# Use the SQLite version (already created)
cd backend
python3 -c "from models import get_user_by_email; print(get_user_by_email('tbobik91@gmail.com'))"
```

The SQLite user is available for local development and testing.

---

## Cost Breakdown

### DynamoDB (Pay-per-request)
- **Writes:** $1.25 per million requests
- **Reads:** $0.25 per million requests
- **Storage:** $0.25 per GB/month

**Example for 1000 users with moderate activity:**
- User creation: 1,000 writes = $0.00125
- Logins: 10,000 reads = $0.0025
- Storage: < 1 MB = $0.0001
- **Total:** ~$0.01/month

### Lambda
- No additional cost - uses existing function

### Total Additional Cost
**~$0.01 - $0.10/month** for DynamoDB user management

---

## Security Features

✅ **Password Hashing** - Bcrypt with salt
✅ **Encrypted Storage** - DynamoDB server-side encryption (SSE)
✅ **Point-in-Time Recovery** - Backup enabled
✅ **IAM Permissions** - Lambda has minimal required permissions
✅ **No Plaintext Passwords** - Stored only as hashes

---

## Troubleshooting

### "Unable to locate credentials"
Configure AWS CLI:
```bash
aws configure
```

### "Requested resource not found"
Deploy the SAM template first to create the DynamoDB table.

### "User already exists"
Use `--verify` flag to check existing user:
```bash
python3 add_user_to_dynamodb.py --email tbobik91@gmail.com --verify --environment prod
```

See `DYNAMODB_USER_SETUP.md` for complete troubleshooting guide.

---

## Summary

✅ **DynamoDB table** added to SAM template
✅ **Lambda permissions** updated for DynamoDB access
✅ **Backend code** supports both SQLite (local) and DynamoDB (AWS)
✅ **Auto-detection** of database backend based on environment
✅ **Scripts created** to manage users in DynamoDB
✅ **Documentation** complete with deployment and usage instructions

**Ready to deploy!** Follow the deployment steps above to create the DynamoDB table and add the user `tbobik91@gmail.com` with free unlimited access.

---

*Created: 2025-11-13*
*For: msg_converter application*
*Purpose: Persistent user management in AWS*
