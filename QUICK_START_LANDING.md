# Quick Start Guide - Subscription Landing Page

Get your subscription landing page up and running in 10 minutes!

## 🎯 Get Your Stripe Keys

Before starting, get your Stripe API keys:

1. Go to [Stripe Dashboard](https://dashboard.stripe.com/test/apikeys)
2. Copy your **Publishable key** (starts with `pk_test_`)
3. Copy your **Secret key** (starts with `sk_test_`)

You'll use these in the deployment steps below.

## 🚀 Deploy in 3 Steps

### Step 1: Setup Stripe Products

```bash
# Set your Stripe key (use YOUR actual key from Stripe Dashboard)
export STRIPE_SECRET_KEY="sk_test_YOUR_KEY_HERE"

# Run setup
cd stripe-setup
pip3 install stripe
python3 setup_stripe_products.py
cd ..
```

This creates your subscription products:
- Monthly: $10/month
- Yearly: $80/year

### Step 2: Deploy Everything

```bash
# Deploy to dev environment
./deploy-landing-page.sh --env dev --region us-east-1
```

This takes ~5 minutes and deploys:
- Backend (Lambda + API Gateway + DynamoDB)
- Frontend (S3 + CloudFront)

### Step 3: Configure Webhook

After deployment completes, you'll see a webhook URL. Configure it:

1. Open: https://dashboard.stripe.com/test/webhooks
2. Click "Add endpoint"
3. Paste the webhook URL
4. Select these events:
   - `checkout.session.completed`
   - `customer.subscription.created`
   - `customer.subscription.updated`
   - `customer.subscription.deleted`
   - `invoice.payment_succeeded`
   - `invoice.payment_failed`
5. Copy the signing secret (starts with `whsec_`)
6. Run:

```bash
sam deploy \
  --template-file aws/template-landing-page.yaml \
  --stack-name subscription-landing-dev \
  --parameter-overrides StripeWebhookSecret="whsec_YOUR_SECRET" \
  --capabilities CAPABILITY_IAM \
  --no-confirm-changeset
```

## ✅ Test Your Setup

Visit your CloudFront URL (shown after deployment):

### Test Free Tier
1. Register account: user@example.com
2. Login
3. Convert 5 emails (free tier limit)
4. Try 6th email - should be blocked

### Test Paid Subscription
1. Click "Upgrade to Monthly"
2. Use test card: `4242 4242 4242 4242`
3. Any future date, any CVC
4. Complete checkout
5. Verify unlimited access

## 📋 What You Get

### Landing Page Features
- ✅ Professional pricing page
- ✅ User registration/login
- ✅ Subscription management dashboard
- ✅ Free tier (5 emails/month)
- ✅ Paid tiers (unlimited)
- ✅ Stripe checkout integration
- ✅ Customer portal for billing
- ✅ Usage tracking and quotas

### Subscription Plans
- **Free**: 5 emails/month
- **Monthly**: $10/month, unlimited
- **Yearly**: $80/year, unlimited (save $40)

## 🔧 Troubleshooting

### Issue: "Stripe products not found"
**Solution**: Run step 1 again to create products

### Issue: "Webhook signature verification failed"
**Solution**: Make sure you completed step 3

### Issue: "Cannot access frontend"
**Solution**: CloudFront takes 5-10 minutes to propagate. Wait a bit.

### Issue: "API errors in browser console"
**Solution**: Check that API Gateway deployed successfully:
```bash
aws cloudformation describe-stacks --stack-name subscription-landing-dev
```

## 📱 Test Cards

Use these Stripe test cards:

| Card Number | Behavior |
|-------------|----------|
| 4242 4242 4242 4242 | Success |
| 4000 0000 0000 0002 | Decline |
| 4000 0025 0000 3155 | 3D Secure |

All cards: any future date, any 3-digit CVC

## 🎉 Next Steps

1. ✅ Test registration and login
2. ✅ Test free tier quota (5 emails)
3. ✅ Test subscription upgrade
4. ✅ Test billing portal
5. ✅ Test subscription cancellation

## 🚢 Deploy to Production

When ready for production:

1. Get live Stripe keys from dashboard
2. Deploy with `--env prod`:

```bash
export STRIPE_SECRET_KEY="sk_live_..."
./deploy-landing-page.sh --env prod --region us-east-1
```

3. Configure webhook with **live mode** URL
4. Test with live cards (small amounts)

## 📚 Full Documentation

See `LANDING_PAGE_README.md` for:
- Complete architecture details
- Security best practices
- Monitoring and alerts
- Production checklist
- Troubleshooting guide

## 🆘 Need Help?

Check these in order:

1. **CloudWatch Logs**: View Lambda errors
   ```bash
   aws logs tail /aws/lambda/landing-checkout-dev --follow
   ```

2. **Stripe Dashboard**: Check webhook attempts
   - https://dashboard.stripe.com/test/webhooks

3. **Stack Status**: Verify deployment
   ```bash
   aws cloudformation describe-stacks --stack-name subscription-landing-dev
   ```

## 📊 Deployment URLs

After deployment, you'll receive:

- **Frontend**: https://xxx.cloudfront.net
- **API**: https://xxx.execute-api.us-east-1.amazonaws.com/dev
- **Webhook**: https://xxx.execute-api.us-east-1.amazonaws.com/dev/api/stripe/webhook

Save these URLs - you'll need them for configuration!

---

**Deployment Time**: ~5 minutes
**Total Setup Time**: ~10 minutes (including webhook configuration)
**Cost**: AWS Free Tier eligible + Stripe fees (2.9% + 30¢)
