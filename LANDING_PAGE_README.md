# Subscription Landing Page - Complete Guide

This guide covers the complete setup and deployment of the Stripe-integrated subscription landing page for the EML to PDF converter.

## 📋 Table of Contents

- [Architecture Overview](#architecture-overview)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Detailed Setup](#detailed-setup)
- [Deployment](#deployment)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Production Checklist](#production-checklist)

## 🏗️ Architecture Overview

The subscription landing page consists of:

### Backend Components
- **DynamoDB**: User database with subscription information
- **Lambda Functions**:
  - Authentication (register, login, verify)
  - Stripe integration (checkout, webhooks, portal)
  - Usage tracking
- **API Gateway**: RESTful API endpoints
- **CloudWatch**: Logging and monitoring

### Frontend Components
- **React Application**: Modern SPA with routing
- **S3 + CloudFront**: Static hosting and CDN
- **Pages**:
  - Landing page with pricing
  - User registration/login
  - Dashboard with subscription management
  - App integration with quota enforcement

### Subscription Tiers
- **Free**: 5 emails/month
- **Monthly**: $10/month - Unlimited emails
- **Yearly**: $80/year - Unlimited emails (save $40)

## ✅ Prerequisites

Before starting, ensure you have:

### Required Software
- AWS CLI (configured with credentials)
- AWS SAM CLI
- Python 3.8+
- Node.js 16+
- Git

### Stripe Account
- Test mode API keys (for dev)
- Live mode API keys (for prod)
- Account in good standing

### AWS Permissions
- CloudFormation
- Lambda
- API Gateway
- DynamoDB
- S3
- CloudFront
- IAM

## 🚀 Quick Start

### 1. Setup Stripe Products

```bash
cd stripe-setup

# Set your Stripe API key (get this from Stripe Dashboard)
export STRIPE_SECRET_KEY="sk_test_YOUR_KEY_HERE"

# Install dependencies and run setup
pip3 install stripe
python3 setup_stripe_products.py
```

This creates:
- Monthly subscription product ($10/month)
- Yearly subscription product ($80/year)
- `stripe_config.json` with product/price IDs

### 2. Deploy to Dev

```bash
# From project root
./deploy-landing-page.sh --env dev --region us-east-1
```

This will:
1. Validate prerequisites
2. Setup Stripe products (if not skipped)
3. Deploy backend infrastructure
4. Build and deploy frontend
5. Display deployment URLs and next steps

### 3. Configure Stripe Webhook

After deployment, you'll see a webhook URL. Configure it in Stripe:

1. Go to [Stripe Webhooks Dashboard](https://dashboard.stripe.com/webhooks)
2. Click "Add endpoint"
3. Enter the webhook URL from deployment output
4. Select events:
   - `checkout.session.completed`
   - `customer.subscription.created`
   - `customer.subscription.updated`
   - `customer.subscription.deleted`
   - `invoice.payment_succeeded`
   - `invoice.payment_failed`
5. Copy the webhook signing secret (starts with `whsec_`)
6. Update your stack:

```bash
sam deploy \
  --template-file aws/template-landing-page.yaml \
  --stack-name subscription-landing-dev \
  --parameter-overrides StripeWebhookSecret=whsec_your_secret_here \
  --capabilities CAPABILITY_IAM \
  --no-confirm-changeset
```

### 4. Test Your Deployment

Visit the CloudFront URL from the deployment output and:
1. Register a new account
2. Login
3. Try converting emails (free tier - 5 emails)
4. Upgrade to a paid plan using Stripe test card: `4242 4242 4242 4242`
5. Verify unlimited access after subscription

## 📖 Detailed Setup

### Environment Variables

The deployment script uses these environment variables:

#### Required
- `STRIPE_SECRET_KEY`: Your Stripe secret key (prompted if not set)

#### Optional
- `AWS_PROFILE`: AWS CLI profile to use
- `AWS_REGION`: AWS region (default: us-east-1)

### Project Structure

```
msg_converter/
├── landing-frontend/              # React frontend
│   ├── src/
│   │   ├── pages/                 # Page components
│   │   │   ├── Home.js           # Landing page
│   │   │   ├── Login.js          # Login page
│   │   │   ├── Register.js       # Registration
│   │   │   ├── Dashboard.js      # User dashboard
│   │   │   └── TryApp.js         # App with quota
│   │   ├── context/
│   │   │   └── AuthContext.js    # Auth state management
│   │   └── App.js                # Main app component
│   └── package.json
│
├── landing-backend/               # Lambda functions
│   ├── handlers/
│   │   ├── auth_handler.py       # Authentication
│   │   └── stripe_handler.py     # Stripe integration
│   ├── models/
│   │   └── user_model.py         # DynamoDB user model
│   └── requirements.txt
│
├── stripe-setup/                  # Stripe configuration
│   ├── setup_stripe_products.py  # Product setup script
│   └── stripe_config.json        # Generated config
│
├── aws/
│   └── template-landing-page.yaml # SAM template
│
└── deploy-landing-page.sh         # Deployment script
```

### Backend API Endpoints

#### Authentication
- `POST /api/auth/register` - Create account
- `POST /api/auth/login` - Login and get JWT
- `GET /api/auth/verify` - Verify JWT token
- `GET /api/auth/usage` - Get usage/quota info

#### Stripe
- `POST /api/stripe/create-checkout-session` - Start subscription
- `POST /api/stripe/webhook` - Stripe events
- `POST /api/stripe/create-portal-session` - Manage billing

### Database Schema

**DynamoDB Table: `subscription-users-{env}`**

```json
{
  "userId": "usr_abc123",
  "email": "user@example.com",
  "passwordHash": "bcrypt_hash",
  "stripeCustomerId": "cus_xyz",
  "subscriptionId": "sub_123",
  "subscriptionStatus": "active",
  "planType": "monthly",
  "emailsUsedThisMonth": 3,
  "usageResetDate": "2025-12-01T00:00:00Z",
  "createdAt": "2025-11-13T12:00:00Z",
  "updatedAt": "2025-11-13T12:00:00Z"
}
```

## 🚢 Deployment

### Dev Environment

```bash
./deploy-landing-page.sh --env dev --region us-east-1
```

### Prod Environment

```bash
# Use live Stripe keys for production
export STRIPE_SECRET_KEY="sk_live_..."

./deploy-landing-page.sh --env prod --region us-east-1
```

### Manual Deployment

If you prefer manual control:

```bash
# 1. Setup Stripe
cd stripe-setup && python3 setup_stripe_products.py && cd ..

# 2. Build backend
sam build --template-file aws/template-landing-page.yaml

# 3. Deploy backend
sam deploy \
  --template-file aws/template-landing-page.yaml \
  --stack-name subscription-landing-dev \
  --parameter-overrides \
    Environment=dev \
    StripeSecretKey="sk_test_..." \
    StripePublishableKey="pk_test_..." \
    MonthlyPriceId="price_..." \
    YearlyPriceId="price_..." \
  --capabilities CAPABILITY_IAM

# 4. Build frontend
cd landing-frontend
npm install
REACT_APP_API_URL="https://your-api-url" \
REACT_APP_STRIPE_PUBLISHABLE_KEY="pk_test_..." \
npm run build

# 5. Deploy frontend
aws s3 sync build/ s3://your-bucket/ --delete
aws cloudfront create-invalidation --distribution-id XXX --paths "/*"
```

### Update Existing Deployment

To update just the frontend:

```bash
cd landing-frontend
npm run build
aws s3 sync build/ s3://your-bucket/ --delete
aws cloudfront create-invalidation --distribution-id XXX --paths "/*"
```

To update just the backend:

```bash
sam build --template-file aws/template-landing-page.yaml
sam deploy --no-confirm-changeset
```

## 🧪 Testing

### Test Card Numbers

Use Stripe test cards for testing:

- **Success**: `4242 4242 4242 4242`
- **Decline**: `4000 0000 0000 0002`
- **3D Secure**: `4000 0025 0000 3155`

Any future expiration date and any 3-digit CVC works.

### Test Scenarios

1. **Free Tier Registration**
   - Register new account
   - Convert 5 emails
   - Verify 6th conversion is blocked

2. **Monthly Subscription**
   - Login as free user
   - Click "Upgrade to Monthly"
   - Complete Stripe checkout
   - Verify unlimited access

3. **Yearly Subscription**
   - Login as free user
   - Click "Upgrade to Yearly"
   - Complete checkout
   - Verify unlimited access

4. **Subscription Management**
   - Login as paid user
   - Click "Manage Billing"
   - Cancel subscription in portal
   - Verify downgrade to free

5. **Webhook Testing**
   - Use [Stripe CLI](https://stripe.com/docs/stripe-cli) to test webhooks locally:
   ```bash
   stripe listen --forward-to localhost:3000/webhook
   stripe trigger payment_intent.succeeded
   ```

### Local Development

Run backend locally:

```bash
cd landing-backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Set environment variables
export USERS_TABLE="subscription-users-dev"
export STRIPE_SECRET_KEY="sk_test_..."
export SECRET_KEY="dev-secret"

# Run with Flask or SAM local
sam local start-api --template aws/template-landing-page.yaml
```

Run frontend locally:

```bash
cd landing-frontend
npm install

# Create .env.local
echo "REACT_APP_API_URL=http://localhost:3000" > .env.local
echo "REACT_APP_STRIPE_PUBLISHABLE_KEY=pk_test_..." >> .env.local

npm start
```

## 🔧 Troubleshooting

### Common Issues

#### 1. Stripe Products Not Found
**Error**: `Price ID not configured`

**Solution**: Run the Stripe setup script:
```bash
cd stripe-setup
python3 setup_stripe_products.py
```

#### 2. JWT Verification Fails
**Error**: `Invalid token`

**Solution**: Ensure `SECRET_KEY` is consistent across deployments. Check CloudFormation parameters.

#### 3. Webhook Signature Verification Fails
**Error**: `Invalid signature`

**Solutions**:
- Ensure webhook secret is configured in Lambda environment
- Verify webhook endpoint URL in Stripe dashboard
- Check that webhook is sending to correct environment (test vs live)

#### 4. CloudFront Not Serving Updated Frontend
**Solution**: Invalidate CloudFront cache:
```bash
aws cloudfront create-invalidation \
  --distribution-id YOUR_DIST_ID \
  --paths "/*"
```

#### 5. DynamoDB Table Not Found
**Error**: `ResourceNotFoundException`

**Solution**: Ensure stack deployed successfully:
```bash
aws cloudformation describe-stacks --stack-name subscription-landing-dev
```

#### 6. CORS Errors
**Solutions**:
- Check API Gateway CORS configuration in template
- Verify frontend is using correct API URL
- Check browser console for specific CORS error

### Debug Mode

Enable debug logging:

```bash
# In Lambda environment variables
DEBUG=true
LOG_LEVEL=DEBUG
```

View logs:

```bash
# API Gateway logs
aws logs tail /aws/apigateway/subscription-landing-api-dev --follow

# Lambda logs
aws logs tail /aws/lambda/landing-checkout-dev --follow
```

## ✅ Production Checklist

Before deploying to production:

### Stripe Configuration
- [ ] Switch to live mode Stripe keys
- [ ] Configure live webhook endpoint
- [ ] Test webhook delivery
- [ ] Set up Stripe billing portal branding
- [ ] Configure email notifications in Stripe

### Security
- [ ] Use strong JWT secret key (not default)
- [ ] Enable CloudFront WAF
- [ ] Review IAM permissions (least privilege)
- [ ] Enable DynamoDB encryption
- [ ] Enable CloudWatch alarms
- [ ] Configure rate limiting on API Gateway

### Frontend
- [ ] Set production API URL
- [ ] Use live Stripe publishable key
- [ ] Update meta tags for SEO
- [ ] Add Google Analytics/tracking
- [ ] Test on multiple browsers/devices

### Backend
- [ ] Set appropriate Lambda timeout/memory
- [ ] Configure dead letter queues
- [ ] Set up CloudWatch alarms for errors
- [ ] Enable X-Ray tracing
- [ ] Configure backup for DynamoDB

### Monitoring
- [ ] CloudWatch dashboard for key metrics
- [ ] Alarms for:
  - Lambda errors
  - API Gateway 5xx errors
  - DynamoDB throttling
  - High response latency
- [ ] Stripe webhook monitoring

### Documentation
- [ ] Document customer support process
- [ ] Create runbook for common issues
- [ ] Document disaster recovery plan

### Testing
- [ ] Complete end-to-end test
- [ ] Load testing
- [ ] Security audit
- [ ] Penetration testing

## 📊 Monitoring

### Key Metrics to Monitor

1. **Subscription Metrics**
   - New signups per day
   - Free to paid conversion rate
   - Churn rate
   - MRR (Monthly Recurring Revenue)

2. **Technical Metrics**
   - API latency
   - Lambda errors
   - DynamoDB read/write capacity
   - CloudFront cache hit rate

3. **Business Metrics**
   - Daily active users
   - Email conversions per user
   - Average quota usage (free tier)

### CloudWatch Dashboard

Create a dashboard with:
- API Gateway request count
- Lambda invocation count and errors
- DynamoDB consumed capacity
- User registration rate

## 🔒 Security Best Practices

1. **Secrets Management**
   - Store Stripe keys in AWS Secrets Manager
   - Rotate JWT secret regularly
   - Never commit secrets to Git

2. **API Security**
   - Rate limit API endpoints
   - Validate all input
   - Use HTTPS only
   - Implement request throttling

3. **Data Protection**
   - Enable DynamoDB encryption
   - Use S3 bucket encryption
   - Enable CloudTrail logging
   - Regular backups

## 🆘 Support

For issues or questions:

1. Check CloudWatch logs
2. Review Stripe dashboard for webhook failures
3. Check deployment-info files for configuration
4. Test with Stripe test cards first

## 📝 License

This project is part of the EML Converter application.

---

**Last Updated**: November 2025
**Version**: 1.0.0
