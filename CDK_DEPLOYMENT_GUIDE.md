# CDK Deployment Guide - Quick Reference

## 🎯 Overview

This CDK app makes it **super easy** to whitelist users for free unlimited access. Just add their email to a config file and deploy!

---

## ⚡ Quick Start (3 Steps)

### 1. Add User to Whitelist

```bash
cd cdk
python3 add_to_whitelist.py --email tbobik91@gmail.com --name "Primary User"
```

### 2. Deploy

```bash
./deploy.sh
```

### 3. Get Password

The password will be shown in the deployment output. Save it and share with the user!

---

## 🎁 What This Gives You

✅ **Automatic User Creation** - Users are created in DynamoDB during deployment
✅ **Random Secure Passwords** - 16-character passwords auto-generated
✅ **Unlimited Access** - Users get `is_unlimited: true`
✅ **Active Subscription** - Users get `subscription_status: active`
✅ **Easy Management** - Simple commands to add/remove users
✅ **Full Infrastructure** - Lambda, API Gateway, DynamoDB, S3, CloudFront

---

## 📝 Adding Multiple Users

### Option 1: Helper Script

```bash
# Add multiple users
python3 add_to_whitelist.py --email user1@example.com --name "User One"
python3 add_to_whitelist.py --email user2@example.com --name "User Two"
python3 add_to_whitelist.py --email user3@example.com --name "User Three"

# View all whitelisted users
python3 add_to_whitelist.py --list

# Deploy once to create all users
./deploy.sh
```

### Option 2: Edit Config File

Edit `cdk/whitelist_config.json`:

```json
{
  "whitelisted_emails": [
    {
      "email": "tbobik91@gmail.com",
      "name": "Primary User",
      "notes": "Free unlimited access"
    },
    {
      "email": "another@example.com",
      "name": "Another User",
      "notes": "VIP customer"
    },
    {
      "email": "third@example.com",
      "name": "Third User"
    }
  ]
}
```

Then deploy:
```bash
./deploy.sh
```

---

## 🔍 Checking Results

### View Deployed Users

```bash
# List whitelisted users
python3 add_to_whitelist.py --list

# Check DynamoDB
aws dynamodb scan \
  --table-name eml-converter-users-prod \
  --filter-expression "is_unlimited = :true" \
  --expression-attribute-values '{":true": {"BOOL": true}}'
```

### Get Passwords

```bash
# View recent deployment logs
aws logs tail /aws/lambda/EmlConverterStack-prod-UserCreatorFunction --follow

# Filter for passwords
aws logs filter-log-events \
  --log-group-name /aws/lambda/EmlConverterStack-prod-UserCreatorFunction \
  --filter-pattern "Password for"
```

---

## 🗑️ Removing Users

### Remove from Whitelist

```bash
python3 add_to_whitelist.py --remove user@example.com
```

### Delete from DynamoDB

```bash
aws dynamodb delete-item \
  --table-name eml-converter-users-prod \
  --key '{"email": {"S": "user@example.com"}}'
```

---

## 🚀 Deployment Options

### Production Deployment

```bash
./deploy.sh
```

### Staging Deployment

```bash
./deploy.sh --environment staging --region us-west-2
```

### Development Deployment

```bash
./deploy.sh --environment dev --region us-east-1
```

---

## 📊 What Gets Created

### DynamoDB Table

```
Table: eml-converter-users-prod
Primary Key: email (String)
GSI: UserIdIndex (user_id)

Attributes:
- email: User's email (primary key)
- user_id: Unique UUID
- password_hash: Bcrypt hashed password
- subscription_status: "active"
- is_unlimited: true
- free_conversions_used: 0
- created_at: ISO timestamp
```

### Lambda Function

```
Name: eml-converter-prod
Memory: 4GB
Timeout: 15 minutes
Runtime: Python 3.12 (Container)
Environment:
  - USERS_TABLE=eml-converter-users-prod
  - S3_BUCKET=eml-converter-temp-prod-*
  - AWS_REGION_NAME=us-east-1
```

### API Gateway

```
Name: eml-converter-api-prod
Endpoints:
  - POST /api/convert
  - POST /api/auth/login
  - POST /api/auth/register
  - GET /api/download/{session_id}/{filename}
  - GET /api/health
```

### CloudFront

```
Distribution for:
- Frontend (S3 origin)
- API (API Gateway origin)
HTTPS enforced
```

---

## 🎯 User Workflow

### For Administrators

1. Add email to whitelist: `python3 add_to_whitelist.py --email user@example.com`
2. Deploy: `./deploy.sh`
3. Get password from logs
4. Share credentials with user:
   - Email: user@example.com
   - Password: <from logs>
   - URL: <CloudFront URL from outputs>

### For End Users

1. Navigate to CloudFront URL
2. Click "Login"
3. Enter email and password
4. Start converting emails with **unlimited access**!

---

## 💡 Key Features

### Automatic User Management

- Users are created automatically during deployment
- No manual DynamoDB operations needed
- Idempotent: Safe to redeploy (won't create duplicates)

### Secure Passwords

- Random 16-character passwords
- Bcrypt hashed in DynamoDB
- Logged to CloudWatch (secure location)
- Cannot be retrieved later (must save during deployment)

### Easy Whitelist Management

- Simple JSON configuration
- Helper script for adding/removing users
- List all whitelisted users with one command

### Production Ready

- Infrastructure as Code (CDK)
- Proper IAM permissions
- Encrypted storage
- CloudWatch logging
- Dead letter queues
- Point-in-time recovery

---

## 📋 Checklist

### Before Deployment

- [ ] AWS CLI configured with credentials
- [ ] Docker installed and running
- [ ] CDK CLI installed: `npm install -g aws-cdk`
- [ ] Users added to whitelist: `python3 add_to_whitelist.py --email user@example.com`
- [ ] Reviewed whitelist: `python3 add_to_whitelist.py --list`

### During Deployment

- [ ] Run: `./deploy.sh`
- [ ] Wait for completion (~10-15 minutes first time)
- [ ] Save passwords from output

### After Deployment

- [ ] Get CloudFront URL from outputs
- [ ] Verify users in DynamoDB
- [ ] Share credentials with users
- [ ] Test login functionality

---

## 🆘 Quick Troubleshooting

### "Unable to locate credentials"
```bash
aws configure
```

### "Docker daemon not running"
Start Docker Desktop or `sudo systemctl start docker`

### "User already exists"
This is normal - users are only created once

### "Password not in logs"
```bash
# Check the correct log group
aws logs describe-log-groups | grep UserCreator

# View all recent logs
aws logs tail /aws/lambda/EmlConverterStack-prod-UserCreatorFunction --follow
```

---

## 🔗 Related Documentation

- **Full CDK Documentation:** `cdk/README.md`
- **DynamoDB Setup Guide:** `DYNAMODB_USER_SETUP.md`
- **AWS Summary:** `AWS_USER_SETUP_SUMMARY.md`
- **Java Migration Guide:** `JAVA-README.md`

---

## 💰 Cost

**~$24/month** for moderate usage (10,000 conversions)

With AWS Free Tier: **~$10-15/month**

---

## 📞 Support

1. Check `cdk/README.md` for detailed documentation
2. View CloudWatch Logs for debugging
3. Check DynamoDB table for user data

---

## ✨ Summary

**Adding whitelisted users is now as simple as:**

```bash
# 1. Add user
python3 add_to_whitelist.py --email user@example.com --name "User Name"

# 2. Deploy
./deploy.sh

# 3. Share credentials (from output)
```

**That's it!** The user now has **free unlimited access forever**! 🎉

---

*Current Whitelisted User: tbobik91@gmail.com*
*Status: Ready for deployment*

---

*Last updated: 2025-11-13*
