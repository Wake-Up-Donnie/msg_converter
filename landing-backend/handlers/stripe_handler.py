"""
Stripe Integration Handlers
Handles checkout session creation, webhooks, and customer portal
"""
import json
import os
import stripe
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

# Stripe Configuration
STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY')
STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET')
MONTHLY_PRICE_ID = os.environ.get('MONTHLY_PRICE_ID')
YEARLY_PRICE_ID = os.environ.get('YEARLY_PRICE_ID')
FRONTEND_URL = os.environ.get('FRONTEND_URL', 'http://localhost:3000')

stripe.api_key = STRIPE_SECRET_KEY

# Import user model
try:
    from ..models.user_model import User
    from .auth_handler import verify_jwt
except ImportError:
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))
    from models.user_model import User
    from handlers.auth_handler import verify_jwt

def create_response(status_code: int, body: Dict[str, Any]) -> Dict[str, Any]:
    """Create API Gateway response"""
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type,Authorization',
            'Access-Control-Allow-Methods': 'GET,POST,OPTIONS'
        },
        'body': json.dumps(body)
    }

def lambda_handler_create_checkout(event, context):
    """
    POST /api/stripe/create-checkout-session
    Create a Stripe Checkout session for subscription
    """
    try:
        # Get and verify JWT token
        auth_header = event.get('headers', {}).get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return create_response(401, {'error': 'Missing authorization token'})

        token = auth_header.replace('Bearer ', '')
        valid, payload = verify_jwt(token)
        if not valid:
            return create_response(401, payload)

        user_id = payload['userId']
        user = User.get_by_id(user_id)
        if not user:
            return create_response(404, {'error': 'User not found'})

        # Parse request body
        body = json.loads(event.get('body', '{}'))
        plan_type = body.get('planType')  # 'monthly' or 'yearly'

        if plan_type not in ['monthly', 'yearly']:
            return create_response(400, {'error': 'Invalid plan type'})

        # Select the appropriate price ID
        price_id = MONTHLY_PRICE_ID if plan_type == 'monthly' else YEARLY_PRICE_ID

        if not price_id:
            return create_response(500, {'error': 'Price ID not configured'})

        # Create or retrieve Stripe customer
        stripe_customer_id = user.get('stripeCustomerId')
        if not stripe_customer_id:
            customer = stripe.Customer.create(
                email=user['email'],
                metadata={'userId': user_id}
            )
            stripe_customer_id = customer.id
            User.update(user_id, {'stripeCustomerId': stripe_customer_id})
        else:
            customer = stripe.Customer.retrieve(stripe_customer_id)

        # Create Checkout Session
        checkout_session = stripe.checkout.Session.create(
            customer=stripe_customer_id,
            mode='subscription',
            payment_method_types=['card'],
            line_items=[{
                'price': price_id,
                'quantity': 1
            }],
            success_url=f"{FRONTEND_URL}/dashboard?session_id={{CHECKOUT_SESSION_ID}}&success=true",
            cancel_url=f"{FRONTEND_URL}/dashboard?canceled=true",
            metadata={
                'userId': user_id,
                'planType': plan_type
            },
            subscription_data={
                'metadata': {
                    'userId': user_id,
                    'planType': plan_type
                }
            }
        )

        logger.info(f"Created checkout session for user {user_id}: {checkout_session.id}")

        return create_response(200, {
            'sessionId': checkout_session.id,
            'url': checkout_session.url
        })

    except stripe.error.StripeError as e:
        logger.error(f"Stripe error in checkout: {e}")
        return create_response(400, {'error': str(e)})
    except Exception as e:
        logger.error(f"Error creating checkout session: {e}")
        return create_response(500, {'error': 'Internal server error'})

def lambda_handler_webhook(event, context):
    """
    POST /api/stripe/webhook
    Handle Stripe webhook events
    """
    try:
        # Get the webhook payload and signature
        payload = event.get('body', '')
        sig_header = event.get('headers', {}).get('Stripe-Signature', '')

        if not sig_header:
            logger.error("Missing Stripe signature header")
            return create_response(400, {'error': 'Missing signature'})

        # Verify webhook signature
        try:
            stripe_event = stripe.Webhook.construct_event(
                payload, sig_header, STRIPE_WEBHOOK_SECRET
            )
        except ValueError as e:
            logger.error(f"Invalid payload: {e}")
            return create_response(400, {'error': 'Invalid payload'})
        except stripe.error.SignatureVerificationError as e:
            logger.error(f"Invalid signature: {e}")
            return create_response(400, {'error': 'Invalid signature'})

        # Handle the event
        event_type = stripe_event['type']
        event_data = stripe_event['data']['object']

        logger.info(f"Received webhook event: {event_type}")

        if event_type == 'checkout.session.completed':
            handle_checkout_completed(event_data)
        elif event_type == 'customer.subscription.created':
            handle_subscription_created(event_data)
        elif event_type == 'customer.subscription.updated':
            handle_subscription_updated(event_data)
        elif event_type == 'customer.subscription.deleted':
            handle_subscription_deleted(event_data)
        elif event_type == 'invoice.payment_succeeded':
            handle_payment_succeeded(event_data)
        elif event_type == 'invoice.payment_failed':
            handle_payment_failed(event_data)
        else:
            logger.info(f"Unhandled event type: {event_type}")

        return create_response(200, {'received': True})

    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return create_response(500, {'error': 'Internal server error'})

def handle_checkout_completed(session):
    """Handle successful checkout"""
    try:
        user_id = session['metadata'].get('userId')
        plan_type = session['metadata'].get('planType')
        customer_id = session['customer']
        subscription_id = session.get('subscription')

        if user_id:
            User.update_stripe_subscription(
                user_id=user_id,
                stripe_customer_id=customer_id,
                subscription_id=subscription_id,
                subscription_status='active',
                plan_type=plan_type
            )
            logger.info(f"Checkout completed for user {user_id}")
    except Exception as e:
        logger.error(f"Error handling checkout completed: {e}")

def handle_subscription_created(subscription):
    """Handle subscription creation"""
    try:
        customer_id = subscription['customer']
        subscription_id = subscription['id']
        status = subscription['status']
        plan_type = subscription['metadata'].get('planType', 'monthly')

        # Find user by Stripe customer ID
        # Note: This requires a GSI on stripeCustomerId if you want efficient lookups
        # For now, we rely on metadata
        user_id = subscription['metadata'].get('userId')

        if user_id:
            User.update_stripe_subscription(
                user_id=user_id,
                stripe_customer_id=customer_id,
                subscription_id=subscription_id,
                subscription_status=status,
                plan_type=plan_type
            )
            logger.info(f"Subscription created for user {user_id}")
    except Exception as e:
        logger.error(f"Error handling subscription created: {e}")

def handle_subscription_updated(subscription):
    """Handle subscription updates"""
    try:
        subscription_id = subscription['id']
        status = subscription['status']
        user_id = subscription['metadata'].get('userId')

        if user_id:
            updates = {
                'subscriptionStatus': status
            }

            # If subscription is canceled or incomplete, downgrade to free
            if status in ['canceled', 'incomplete_expired', 'unpaid']:
                updates['planType'] = 'free'

            User.update(user_id, updates)
            logger.info(f"Subscription updated for user {user_id}: {status}")
    except Exception as e:
        logger.error(f"Error handling subscription updated: {e}")

def handle_subscription_deleted(subscription):
    """Handle subscription cancellation"""
    try:
        user_id = subscription['metadata'].get('userId')

        if user_id:
            User.cancel_subscription(user_id)
            logger.info(f"Subscription deleted for user {user_id}")
    except Exception as e:
        logger.error(f"Error handling subscription deleted: {e}")

def handle_payment_succeeded(invoice):
    """Handle successful payment"""
    try:
        subscription_id = invoice.get('subscription')
        if subscription_id:
            subscription = stripe.Subscription.retrieve(subscription_id)
            user_id = subscription['metadata'].get('userId')

            if user_id:
                User.update(user_id, {'subscriptionStatus': 'active'})
                logger.info(f"Payment succeeded for user {user_id}")
    except Exception as e:
        logger.error(f"Error handling payment succeeded: {e}")

def handle_payment_failed(invoice):
    """Handle failed payment"""
    try:
        subscription_id = invoice.get('subscription')
        if subscription_id:
            subscription = stripe.Subscription.retrieve(subscription_id)
            user_id = subscription['metadata'].get('userId')

            if user_id:
                User.update(user_id, {'subscriptionStatus': 'past_due'})
                logger.info(f"Payment failed for user {user_id}")
    except Exception as e:
        logger.error(f"Error handling payment failed: {e}")

def lambda_handler_create_portal(event, context):
    """
    POST /api/stripe/create-portal-session
    Create a customer portal session for subscription management
    """
    try:
        # Get and verify JWT token
        auth_header = event.get('headers', {}).get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return create_response(401, {'error': 'Missing authorization token'})

        token = auth_header.replace('Bearer ', '')
        valid, payload = verify_jwt(token)
        if not valid:
            return create_response(401, payload)

        user_id = payload['userId']
        user = User.get_by_id(user_id)
        if not user:
            return create_response(404, {'error': 'User not found'})

        stripe_customer_id = user.get('stripeCustomerId')
        if not stripe_customer_id:
            return create_response(400, {'error': 'No active subscription found'})

        # Create portal session
        portal_session = stripe.billing_portal.Session.create(
            customer=stripe_customer_id,
            return_url=f"{FRONTEND_URL}/dashboard"
        )

        logger.info(f"Created portal session for user {user_id}")

        return create_response(200, {
            'url': portal_session.url
        })

    except stripe.error.StripeError as e:
        logger.error(f"Stripe error in portal: {e}")
        return create_response(400, {'error': str(e)})
    except Exception as e:
        logger.error(f"Error creating portal session: {e}")
        return create_response(500, {'error': 'Internal server error'})

# Main Lambda handlers for AWS
def checkout_handler(event, context):
    """AWS Lambda entry point for checkout"""
    return lambda_handler_create_checkout(event, context)

def webhook_handler(event, context):
    """AWS Lambda entry point for webhooks"""
    return lambda_handler_webhook(event, context)

def portal_handler(event, context):
    """AWS Lambda entry point for customer portal"""
    return lambda_handler_create_portal(event, context)
