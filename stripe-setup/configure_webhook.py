#!/usr/bin/env python3
"""
Stripe Webhook Configuration Script
Automates webhook endpoint creation and Lambda function configuration
"""
import stripe
import os
import sys
import json
import boto3

def configure_webhook(environment='dev', region='us-east-1'):
    """Configure Stripe webhook and update Lambda function"""

    # Get Stripe API key from environment
    stripe_secret_key = os.environ.get('STRIPE_SECRET_KEY')
    if not stripe_secret_key:
        print("❌ Error: STRIPE_SECRET_KEY environment variable not set")
        sys.exit(1)

    stripe.api_key = stripe_secret_key

    # Load deployment info to get webhook URL
    deployment_info_file = f'../deployment-info-{environment}.txt'
    if not os.path.exists(deployment_info_file):
        print(f"❌ Error: Deployment info file not found: {deployment_info_file}")
        print("Please run the deployment script first")
        sys.exit(1)

    # Parse deployment info to get webhook URL
    webhook_url = None
    with open(deployment_info_file, 'r') as f:
        for line in f:
            if line.startswith('Webhook URL:'):
                webhook_url = line.split(':', 1)[1].strip()
                break

    if not webhook_url:
        print("❌ Error: Could not find Webhook URL in deployment info")
        sys.exit(1)

    print("🔧 Configuring Stripe Webhook Endpoint...")
    print(f"Webhook URL: {webhook_url}")
    print(f"Environment: {environment}")
    print("")

    # Events to subscribe to
    events = [
        'checkout.session.completed',
        'customer.subscription.created',
        'customer.subscription.updated',
        'customer.subscription.deleted',
        'invoice.payment_succeeded',
        'invoice.payment_failed',
    ]

    try:
        # Check if webhook already exists
        print("📋 Checking for existing webhook endpoints...")
        existing_webhooks = stripe.WebhookEndpoint.list(limit=100)

        webhook_endpoint = None
        for webhook in existing_webhooks.data:
            if webhook.url == webhook_url:
                print(f"✅ Found existing webhook endpoint: {webhook.id}")
                webhook_endpoint = webhook
                break

        # Create webhook if it doesn't exist
        if not webhook_endpoint:
            print("\n📦 Creating new webhook endpoint...")
            webhook_endpoint = stripe.WebhookEndpoint.create(
                url=webhook_url,
                enabled_events=events,
                description=f"EML Converter Subscription Webhook - {environment}",
            )
            print(f"✅ Webhook endpoint created: {webhook_endpoint.id}")
        else:
            # Update existing webhook to ensure it has all required events
            print("\n🔄 Updating webhook endpoint events...")
            webhook_endpoint = stripe.WebhookEndpoint.modify(
                webhook_endpoint.id,
                enabled_events=events,
            )
            print("✅ Webhook endpoint updated")

        # Get the webhook secret
        webhook_secret = webhook_endpoint.secret
        print(f"\n🔑 Webhook Secret: {webhook_secret[:20]}...")

        # Load Stripe config for price IDs
        if os.path.exists('stripe_config.json'):
            with open('stripe_config.json', 'r') as f:
                stripe_config = json.load(f)
            monthly_price_id = stripe_config['monthly_price_id']
            yearly_price_id = stripe_config['yearly_price_id']
        else:
            print("⚠️  Warning: stripe_config.json not found, using placeholder price IDs")
            monthly_price_id = "PLACEHOLDER_MONTHLY"
            yearly_price_id = "PLACEHOLDER_YEARLY"

        # Update Lambda function with webhook secret
        print("\n🔧 Updating Lambda function configuration...")
        lambda_client = boto3.client('lambda', region_name=region)

        function_name = f'landing-webhook-{environment}'

        # Get current Lambda configuration to preserve other env vars
        try:
            response = lambda_client.get_function_configuration(
                FunctionName=function_name
            )
            current_env = response.get('Environment', {}).get('Variables', {})

            # Update with webhook secret
            current_env['STRIPE_WEBHOOK_SECRET'] = webhook_secret

            # Update Lambda function
            lambda_client.update_function_configuration(
                FunctionName=function_name,
                Environment={
                    'Variables': current_env
                }
            )
            print(f"✅ Lambda function '{function_name}' updated with webhook secret")

        except lambda_client.exceptions.ResourceNotFoundException:
            print(f"❌ Error: Lambda function '{function_name}' not found")
            print("Please check that the deployment completed successfully")
            sys.exit(1)

        # Save webhook info
        webhook_info = {
            'webhook_id': webhook_endpoint.id,
            'webhook_url': webhook_url,
            'webhook_secret': webhook_secret,
            'environment': environment,
            'enabled_events': events,
        }

        with open(f'webhook_config_{environment}.json', 'w') as f:
            json.dump(webhook_info, f, indent=2)

        print("\n" + "="*60)
        print("🎉 Webhook Configuration Complete!")
        print("="*60)
        print(f"\n📋 Webhook Details:")
        print(f"   Endpoint ID: {webhook_endpoint.id}")
        print(f"   URL: {webhook_url}")
        print(f"   Status: {'Enabled' if webhook_endpoint.status == 'enabled' else 'Disabled'}")
        print(f"\n📝 Subscribed Events:")
        for event in events:
            print(f"   ✓ {event}")
        print(f"\n💾 Configuration saved to: webhook_config_{environment}.json")
        print("\n✅ Your webhook is now configured and ready to receive events!")
        print("="*60)

        return webhook_endpoint

    except stripe.error.StripeError as e:
        print(f"\n❌ Stripe Error: {e}")
        return None
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Configure Stripe webhook endpoint')
    parser.add_argument('--env', default='dev', choices=['dev', 'prod'],
                      help='Environment (dev or prod)')
    parser.add_argument('--region', default='us-east-1',
                      help='AWS region')

    args = parser.parse_args()

    configure_webhook(environment=args.env, region=args.region)
