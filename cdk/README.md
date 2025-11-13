# EML Converter CDK Deployment

AWS CDK application for deploying the EML/MSG to PDF converter with DynamoDB user management and automatic whitelisted user creation.

## 🚀 Quick Start

### Prerequisites

- **Node.js** 14+ and npm
- **Python** 3.8+
- **AWS CLI** configured with credentials
- **Docker** installed and running
- **AWS CDK** CLI installed: `npm install -g aws-cdk`

### 1. Add Users to Whitelist

```bash
# Add a single user
python3 add_to_whitelist.py \
  --email tbobik91@gmail.com \
  --name "Primary User" \
  --notes "Free unlimited access"

# Add more users
python3 add_to_whitelist.py \
  --email another@example.com \
  --name "Another User"

# List all whitelisted users
python3 add_to_whitelist.py --list
```

### 2. Deploy the Stack

```bash
# Deploy to production
./deploy.sh

# Or deploy to a specific environment
./deploy.sh --environment staging --region us-west-2
```

### 3. Get User Passwords

The deployment script will automatically show passwords in the output. You can also check CloudWatch Logs:

```bash
# View logs for user passwords
aws logs tail /aws/lambda/EmlConverterStack-prod-UserCreatorFunction --follow
```

---

## 📋 What Gets Deployed

### Infrastructure

| Resource | Description |
|----------|-------------|
| **DynamoDB Table** | User management (`eml-converter-users-{env}`) |
| **Lambda Function** | Containerized EML converter (4GB RAM, 15min timeout) |
| **API Gateway** | REST API with CORS enabled |
| **CloudFront** | CDN for frontend and API |
| **S3 Buckets** | Temp files (1-day retention) + Frontend hosting |
| **ECR Repository** | Docker image storage |
| **SQS Queue** | Dead letter queue for failed Lambda executions |
| **CloudWatch Logs** | Logging with 30-day retention |

### Automatic User Creation

When you deploy, the stack automatically:
1. Reads `whitelist_config.json`
2. Creates users in DynamoDB with:
   - Random secure passwords (16-character)
   - `subscription_status: active`
   - `is_unlimited: true`
   - `free_conversions_used: 0`
3. Logs passwords to CloudWatch
4. Outputs summary of created users

---

## 🔧 Configuration

### Whitelist Configuration

**File:** `whitelist_config.json`

```json
{
  "description": "Whitelist configuration for free unlimited users",
  "whitelisted_emails": [
    {
      "email": "user@example.com",
      "name": "User Name",
      "notes": "Free unlimited access granted on 2025-11-13"
    }
  ]
}
```

### Environment Variables

The Lambda function receives these environment variables:

- `S3_BUCKET` - Temporary file storage bucket
- `ENVIRONMENT` - Environment name (dev/staging/prod)
- `PLAYWRIGHT_BROWSERS_PATH` - Path to Chromium binary
- `USERS_TABLE` - DynamoDB table name
- `AWS_REGION_NAME` - AWS region

---

## 📖 Usage Guide

### Adding Whitelisted Users

#### Method 1: Using the Helper Script (Recommended)

```bash
# Add a user
python3 add_to_whitelist.py \
  --email newuser@example.com \
  --name "New User" \
  --notes "VIP customer"

# Deploy to create the user
./deploy.sh
```

#### Method 2: Manual Edit

1. Edit `whitelist_config.json`
2. Add email to `whitelisted_emails` array:
   ```json
   {
     "email": "newuser@example.com",
     "name": "New User",
     "notes": "VIP customer"
   }
   ```
3. Deploy: `./deploy.sh`

### Removing Users from Whitelist

```bash
# Remove from whitelist config
python3 add_to_whitelist.py --remove user@example.com

# Optionally delete from DynamoDB
aws dynamodb delete-item \
  --table-name eml-converter-users-prod \
  --key '{"email": {"S": "user@example.com"}}'
```

### Viewing Whitelisted Users

```bash
# List users in whitelist config
python3 add_to_whitelist.py --list

# Query DynamoDB for all users
aws dynamodb scan \
  --table-name eml-converter-users-prod \
  --filter-expression "is_unlimited = :true" \
  --expression-attribute-values '{":true": {"BOOL": true}}'
```

### Retrieving User Passwords

Passwords are shown during deployment. To retrieve later:

```bash
# View CloudWatch Logs (recent deployments only)
aws logs filter-log-events \
  --log-group-name /aws/lambda/EmlConverterStack-prod-UserCreatorFunction \
  --filter-pattern "Password for" \
  --start-time $(($(date +%s) * 1000 - 3600000)) \
  --query 'events[*].message' \
  --output text
```

**Note:** Passwords cannot be retrieved from DynamoDB (they are hashed).

---

## 🛠️ Deployment Commands

### Initial Deployment

```bash
# Install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Bootstrap CDK (first time only)
cdk bootstrap

# Deploy
./deploy.sh
```

### Update Deployment

```bash
# After modifying whitelist_config.json or code
./deploy.sh
```

### Deploy to Different Environment

```bash
# Staging
./deploy.sh --environment staging --region us-west-2

# Development
./deploy.sh --environment dev --region us-east-1
```

### View Stack Differences

```bash
cdk diff --context environment=prod
```

### Destroy Stack

```bash
cdk destroy --context environment=prod
```

**Warning:** This will delete all resources except:
- DynamoDB table (retained with user data)
- ECR repository (retained with images)

---

## 📊 Monitoring

### CloudWatch Logs

```bash
# Lambda function logs
aws logs tail /aws/lambda/eml-converter-prod --follow

# User creator logs
aws logs tail /aws/lambda/EmlConverterStack-prod-UserCreatorFunction --follow

# API Gateway logs
aws logs tail /aws/apigateway/eml-converter-api-prod --follow
```

### Metrics

```bash
# Lambda invocations
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Invocations \
  --dimensions Name=FunctionName,Value=eml-converter-prod \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Sum
```

### DynamoDB

```bash
# View table details
aws dynamodb describe-table --table-name eml-converter-users-prod

# Count users
aws dynamodb scan \
  --table-name eml-converter-users-prod \
  --select COUNT
```

---

## 💰 Cost Estimation

### Monthly Costs (Moderate Usage)

| Service | Usage | Cost |
|---------|-------|------|
| Lambda | 10,000 requests @ 30s avg, 4GB | ~$8 |
| API Gateway | 10,000 requests | ~$0.04 |
| S3 Storage | 100GB temp (avg) | ~$2.30 |
| S3 Requests | 20,000 PUT/GET | ~$0.10 |
| CloudFront | 100GB transfer | ~$8.50 |
| DynamoDB | 10,000 reads/writes | ~$0.03 |
| CloudWatch Logs | 10GB | ~$5 |
| **Total** | | **~$24/month** |

### Free Tier Benefits

If within AWS Free Tier:
- Lambda: 1M requests/month free
- DynamoDB: 25GB storage + 25 WCU/RCU free
- CloudFront: 1TB transfer/month free (first year)

**Estimated cost with Free Tier: $10-15/month**

---

## 🔐 Security

### Password Security

- Passwords are **bcrypt hashed** before storage
- Random 16-character passwords generated
- Passwords logged to CloudWatch (secure location)
- DynamoDB encryption at rest enabled

### IAM Permissions

The Lambda function has minimal permissions:
- Read/write access to DynamoDB users table
- Read/write access to S3 temp bucket
- CloudWatch Logs write access

### Network Security

- API Gateway with CORS enabled (configurable)
- CloudFront with HTTPS enforced
- S3 buckets with encryption enabled

---

## 🐛 Troubleshooting

### Error: "Unable to locate credentials"

**Solution:**
```bash
aws configure
```

### Error: "Docker daemon not running"

**Solution:**
```bash
# macOS/Windows
# Start Docker Desktop

# Linux
sudo systemctl start docker
```

### Error: "CDK bootstrap required"

**Solution:**
```bash
cdk bootstrap aws://ACCOUNT_ID/REGION
```

### Error: "User already exists"

This is normal - the custom resource detects existing users and skips them.

### Password Not Showing in Logs

Check the correct log group:
```bash
aws logs describe-log-groups --log-group-name-prefix "/aws/lambda/EmlConverter"
```

### Lambda Function Failing

Check logs:
```bash
aws logs tail /aws/lambda/eml-converter-prod --follow
```

Common issues:
- Container image not pushed to ECR
- Insufficient memory (increase to 4GB+)
- Timeout (increase to 15 minutes)

---

## 📁 Project Structure

```
cdk/
├── app.py                      # CDK app entry point
├── cdk.json                    # CDK configuration
├── requirements.txt            # Python dependencies
├── whitelist_config.json       # Whitelisted users configuration
├── add_to_whitelist.py         # Helper script to add users
├── deploy.sh                   # Deployment script
├── stacks/
│   ├── __init__.py
│   └── eml_converter_stack.py  # Main CDK stack definition
└── lambda/
    └── user_creator/
        ├── index.py            # Custom resource Lambda
        └── requirements.txt    # Lambda dependencies
```

---

## 🔄 Workflow

### Adding a New Whitelisted User

```bash
# 1. Add user to whitelist
python3 add_to_whitelist.py --email newuser@example.com --name "New User"

# 2. Deploy stack (creates user in DynamoDB)
./deploy.sh

# 3. Get password from logs
aws logs filter-log-events \
  --log-group-name /aws/lambda/EmlConverterStack-prod-UserCreatorFunction \
  --filter-pattern "Password for newuser@example.com"

# 4. Share credentials securely with user
# Email: newuser@example.com
# Password: <from logs>
# URL: <CloudFront URL from outputs>

# 5. User logs in and has unlimited access!
```

### Updating Infrastructure

```bash
# 1. Modify stack in stacks/eml_converter_stack.py

# 2. View changes
cdk diff --context environment=prod

# 3. Deploy
./deploy.sh

# 4. Verify
aws cloudformation describe-stacks --stack-name EmlConverterStack-prod
```

---

## 📚 Additional Resources

- [AWS CDK Documentation](https://docs.aws.amazon.com/cdk/)
- [DynamoDB Best Practices](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/best-practices.html)
- [Lambda Container Images](https://docs.aws.amazon.com/lambda/latest/dg/images-create.html)

---

## 🆘 Support

For issues or questions:
1. Check CloudWatch Logs
2. Review this README
3. Check the main project documentation in `/DYNAMODB_USER_SETUP.md`
4. Open a GitHub issue

---

## 📝 Notes

- **User Retention:** Users in DynamoDB are retained even if the stack is destroyed
- **Password Recovery:** Passwords cannot be recovered after initial creation (they are hashed)
- **Deployment Time:** Initial deployment takes ~10-15 minutes
- **Updates:** Subsequent deployments are faster (~3-5 minutes)
- **Whitelist Changes:** Redeploy the stack to create newly whitelisted users

---

*Last updated: 2025-11-13*
