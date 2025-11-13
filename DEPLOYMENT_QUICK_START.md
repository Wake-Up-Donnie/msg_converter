# Deployment Quick Start Guide

## 🚀 Deploy with Whitelisted Users (One Command!)

Your deployment now **automatically creates whitelisted users** in DynamoDB!

---

## ⚡ Quick Deploy

```bash
./deploy.sh dev us-east-1 "mysecretpassword"
```

That's it! This single command:
1. ✅ Deploys infrastructure (Lambda, DynamoDB, API Gateway, CloudFront, S3)
2. ✅ **Automatically creates whitelisted users in DynamoDB**
3. ✅ Shows passwords in output
4. ✅ Saves credentials to file

---

## 📝 Before First Deploy: Add Users to Whitelist

### Quick Method

```bash
cd cdk
python3 add_to_whitelist.py --email tbobik91@gmail.com --name "Primary User"
```

**Output:**
```
✓ Added tbobik91@gmail.com to whitelist
  Total whitelisted users: 1
```

### Add Multiple Users

```bash
python3 add_to_whitelist.py --email user1@example.com --name "User One"
python3 add_to_whitelist.py --email user2@example.com --name "User Two"
python3 add_to_whitelist.py --email user3@example.com --name "User Three"

# List all
python3 add_to_whitelist.py --list
```

### Manual Method

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
      "name": "Another User"
    }
  ]
}
```

---

## 🎯 Deploy Commands

### Development

```bash
./deploy.sh dev us-east-1 "mysecretpassword"
```

### Staging

```bash
./deploy.sh staging us-west-2 "mystagingpass"
```

### Production (no password)

```bash
./deploy.sh prod us-east-1
```

---

## 📋 What Happens During Deployment

### Step 1: Infrastructure Deployment
- Builds Docker image with Playwright
- Pushes to ECR
- Deploys SAM template (Lambda, API Gateway, DynamoDB, S3, CloudFront)
- Deploys React frontend to S3
- Invalidates CloudFront cache

### Step 2: Whitelisted User Creation ✨
- Reads `cdk/whitelist_config.json`
- Creates each user in DynamoDB with:
  - Random 16-character password
  - `subscription_status: active`
  - `is_unlimited: true`
  - `free_conversions_used: 0`
- Saves passwords to `whitelisted_users_credentials_{environment}.txt`
- Displays credentials in terminal

### Step 3: Summary
- Shows CloudFront URL
- Shows DynamoDB table name
- Shows user counts
- Provides next steps

---

## 🔐 Getting User Credentials

### During Deployment

Passwords are displayed in the terminal output:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Whitelisted User Credentials
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Email: tbobik91@gmail.com
Password: XyZ123AbC456DeF7

⚠ IMPORTANT: Save these passwords securely!
Credentials saved to: ./whitelisted_users_credentials_dev.txt
```

### After Deployment

```bash
# View saved credentials
cat whitelisted_users_credentials_dev.txt

# Verify user in DynamoDB
python3 backend/add_user_to_dynamodb.py \
  --email tbobik91@gmail.com \
  --verify \
  --environment dev \
  --region us-east-1
```

---

## 🔄 Adding More Users Later

### Option 1: Add to Whitelist & Redeploy

```bash
# Add new user to whitelist
cd cdk
python3 add_to_whitelist.py --email newuser@example.com

# Redeploy (creates new user automatically)
cd ..
./deploy.sh dev us-east-1 "mysecretpassword"
```

### Option 2: Manual Creation

```bash
# Create user directly in DynamoDB
python3 backend/add_user_to_dynamodb.py \
  --email newuser@example.com \
  --environment dev \
  --region us-east-1
```

---

## 🗑️ Removing Users

### Remove from Whitelist

```bash
cd cdk
python3 add_to_whitelist.py --remove user@example.com
```

**Note:** This only removes from whitelist config. User remains in DynamoDB.

### Delete from DynamoDB

```bash
aws dynamodb delete-item \
  --table-name eml-converter-users-dev \
  --key '{"email": {"S": "user@example.com"}}' \
  --region us-east-1
```

---

## 📊 Verify Deployment

### Check Users in DynamoDB

```bash
# Count all users
aws dynamodb scan \
  --table-name eml-converter-users-dev \
  --select COUNT \
  --region us-east-1

# List all unlimited users
aws dynamodb scan \
  --table-name eml-converter-users-dev \
  --filter-expression "is_unlimited = :true" \
  --expression-attribute-values '{":true": {"BOOL": true}}' \
  --region us-east-1
```

### Test Login

```bash
# Get CloudFront URL
CLOUDFRONT_URL=$(aws cloudformation describe-stacks \
  --stack-name eml-converter-dev \
  --query "Stacks[0].Outputs[?OutputKey=='CloudFrontURL'].OutputValue" \
  --output text \
  --region us-east-1)

echo "Application URL: $CLOUDFRONT_URL"

# Test API login
curl -X POST "${CLOUDFRONT_URL}/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "tbobik91@gmail.com",
    "password": "YOUR_PASSWORD_HERE"
  }'
```

---

## 🎁 Features

### Automatic User Creation
- ✅ Users created during deployment
- ✅ No manual DynamoDB operations needed
- ✅ Idempotent (safe to redeploy)
- ✅ Won't create duplicates

### Secure Password Management
- ✅ Random 16-character passwords
- ✅ Bcrypt hashed in DynamoDB
- ✅ Saved to local file
- ✅ Displayed in terminal

### Easy Whitelist Management
- ✅ Simple JSON configuration
- ✅ Helper script for add/remove
- ✅ List all whitelisted users

### Unlimited Access
- ✅ `subscription_status: active`
- ✅ `is_unlimited: true`
- ✅ No conversion limits
- ✅ No expiration

---

## 🆘 Troubleshooting

### "No whitelist configuration found"

**Solution:**
```bash
cd cdk
python3 add_to_whitelist.py --email user@example.com
cd ..
./deploy.sh dev us-east-1 "password"
```

### "User already exists"

This is normal - users are only created once. The script detects existing users and skips them.

### "Unable to locate credentials"

**Solution:**
```bash
aws configure
```

### Credentials File Not Created

Check if any users were created:
```bash
cat whitelisted_users_credentials_dev.txt
```

If empty, users may already exist. Verify:
```bash
python3 backend/add_user_to_dynamodb.py --email user@example.com --verify --environment dev
```

### Password Not Showing

Users might already exist. To reset password, delete and recreate:
```bash
# Delete from DynamoDB
aws dynamodb delete-item \
  --table-name eml-converter-users-dev \
  --key '{"email": {"S": "user@example.com"}}'

# Redeploy to recreate
./deploy.sh dev us-east-1 "password"
```

---

## 📁 File Structure

```
msg_converter/
├── deploy.sh                                    # 👈 NEW: Main deployment script
├── aws/
│   └── deploy-container.sh                      # Infrastructure deployment
├── backend/
│   └── add_user_to_dynamodb.py                  # User creation script
├── cdk/
│   ├── whitelist_config.json                    # 👈 Whitelist configuration
│   └── add_to_whitelist.py                      # 👈 Helper to manage whitelist
└── whitelisted_users_credentials_dev.txt        # 👈 NEW: Saved passwords (gitignored)
```

---

## 🔗 Related Documentation

- **Full CDK Guide:** `cdk/README.md`
- **CDK Quick Reference:** `CDK_DEPLOYMENT_GUIDE.md`
- **DynamoDB Setup:** `DYNAMODB_USER_SETUP.md`
- **AWS Summary:** `AWS_USER_SETUP_SUMMARY.md`

---

## ✨ Summary

**Deployment is now a simple 2-step process:**

1. **Add users to whitelist:**
   ```bash
   cd cdk
   python3 add_to_whitelist.py --email tbobik91@gmail.com
   cd ..
   ```

2. **Deploy everything:**
   ```bash
   ./deploy.sh dev us-east-1 "mysecretpassword"
   ```

**Result:** Infrastructure deployed + Users created + Passwords saved ✅

---

## 🎯 Current Configuration

**Pre-configured whitelisted user:**
- Email: `tbobik91@gmail.com`
- Status: Ready for deployment
- Access: Unlimited (free forever)

**Ready to deploy with:**
```bash
./deploy.sh dev us-east-1 "mysecretpassword"
```

---

*Last updated: 2025-11-13*
*For your exact command: `./deploy.sh dev us-east-1 "mysecretpassword"`*
