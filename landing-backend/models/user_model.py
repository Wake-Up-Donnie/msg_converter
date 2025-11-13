"""
User Model for DynamoDB
Handles all user-related database operations
"""
import boto3
import os
import uuid
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Optional, Dict, Any
import logging

logger = logging.getLogger(__name__)

# DynamoDB configuration
USERS_TABLE = os.environ.get('USERS_TABLE', 'subscription-users-dev')
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(USERS_TABLE)

class User:
    """User model for subscription management"""

    @staticmethod
    def create(email: str, password_hash: str) -> Dict[str, Any]:
        """Create a new user"""
        user_id = f"usr_{uuid.uuid4().hex}"
        now = datetime.utcnow().isoformat()

        # Calculate first usage reset date (next month)
        reset_date = (datetime.utcnow() + timedelta(days=30)).isoformat()

        user_data = {
            'userId': user_id,
            'email': email,
            'passwordHash': password_hash,
            'stripeCustomerId': None,
            'subscriptionId': None,
            'subscriptionStatus': 'none',
            'planType': 'free',
            'emailsUsedThisMonth': 0,
            'usageResetDate': reset_date,
            'createdAt': now,
            'updatedAt': now
        }

        try:
            table.put_item(Item=user_data)
            logger.info(f"Created user: {user_id} ({email})")
            return user_data
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            raise

    @staticmethod
    def get_by_id(user_id: str) -> Optional[Dict[str, Any]]:
        """Get user by ID"""
        try:
            response = table.get_item(Key={'userId': user_id})
            return response.get('Item')
        except Exception as e:
            logger.error(f"Error getting user by ID {user_id}: {e}")
            return None

    @staticmethod
    def get_by_email(email: str) -> Optional[Dict[str, Any]]:
        """Get user by email"""
        try:
            response = table.query(
                IndexName='EmailIndex',
                KeyConditionExpression='email = :email',
                ExpressionAttributeValues={':email': email}
            )
            items = response.get('Items', [])
            return items[0] if items else None
        except Exception as e:
            logger.error(f"Error getting user by email {email}: {e}")
            return None

    @staticmethod
    def update(user_id: str, updates: Dict[str, Any]) -> bool:
        """Update user attributes"""
        try:
            # Build update expression
            update_expr_parts = []
            expr_attr_values = {}

            # Always update the updatedAt timestamp
            updates['updatedAt'] = datetime.utcnow().isoformat()

            for key, value in updates.items():
                update_expr_parts.append(f"{key} = :{key}")
                expr_attr_values[f":{key}"] = value

            update_expression = "SET " + ", ".join(update_expr_parts)

            table.update_item(
                Key={'userId': user_id},
                UpdateExpression=update_expression,
                ExpressionAttributeValues=expr_attr_values
            )
            logger.info(f"Updated user {user_id}: {updates.keys()}")
            return True
        except Exception as e:
            logger.error(f"Error updating user {user_id}: {e}")
            return False

    @staticmethod
    def increment_email_count(user_id: str) -> Dict[str, Any]:
        """Increment email conversion count"""
        try:
            response = table.update_item(
                Key={'userId': user_id},
                UpdateExpression="SET emailsUsedThisMonth = emailsUsedThisMonth + :inc, updatedAt = :now",
                ExpressionAttributeValues={
                    ':inc': 1,
                    ':now': datetime.utcnow().isoformat()
                },
                ReturnValues='ALL_NEW'
            )
            return response['Attributes']
        except Exception as e:
            logger.error(f"Error incrementing email count for {user_id}: {e}")
            raise

    @staticmethod
    def reset_usage_if_needed(user_id: str) -> bool:
        """Reset monthly usage if reset date has passed"""
        try:
            user = User.get_by_id(user_id)
            if not user:
                return False

            reset_date = datetime.fromisoformat(user['usageResetDate'])
            now = datetime.utcnow()

            if now >= reset_date:
                # Reset usage and set next reset date
                next_reset = (now + timedelta(days=30)).isoformat()
                User.update(user_id, {
                    'emailsUsedThisMonth': 0,
                    'usageResetDate': next_reset
                })
                logger.info(f"Reset usage for user {user_id}")
                return True

            return False
        except Exception as e:
            logger.error(f"Error resetting usage for {user_id}: {e}")
            return False

    @staticmethod
    def check_quota(user_id: str) -> Dict[str, Any]:
        """Check if user has quota available"""
        try:
            user = User.get_by_id(user_id)
            if not user:
                return {'allowed': False, 'error': 'User not found'}

            # Reset usage if needed
            User.reset_usage_if_needed(user_id)

            # Refresh user data after potential reset
            user = User.get_by_id(user_id)

            # Paid plans have unlimited usage
            if user['planType'] in ['monthly', 'yearly']:
                return {
                    'allowed': True,
                    'unlimited': True,
                    'planType': user['planType'],
                    'subscriptionStatus': user['subscriptionStatus']
                }

            # Free plan has 5 emails per month
            emails_used = user.get('emailsUsedThisMonth', 0)
            if emails_used < 5:
                return {
                    'allowed': True,
                    'unlimited': False,
                    'remaining': 5 - emails_used,
                    'used': emails_used,
                    'planType': 'free'
                }

            return {
                'allowed': False,
                'unlimited': False,
                'remaining': 0,
                'used': emails_used,
                'planType': 'free',
                'error': 'Free tier limit reached. Please upgrade to continue.'
            }
        except Exception as e:
            logger.error(f"Error checking quota for {user_id}: {e}")
            return {'allowed': False, 'error': str(e)}

    @staticmethod
    def update_stripe_subscription(
        user_id: str,
        stripe_customer_id: str,
        subscription_id: str,
        subscription_status: str,
        plan_type: str
    ) -> bool:
        """Update user's Stripe subscription information"""
        return User.update(user_id, {
            'stripeCustomerId': stripe_customer_id,
            'subscriptionId': subscription_id,
            'subscriptionStatus': subscription_status,
            'planType': plan_type
        })

    @staticmethod
    def cancel_subscription(user_id: str) -> bool:
        """Cancel user's subscription (downgrade to free)"""
        return User.update(user_id, {
            'subscriptionStatus': 'canceled',
            'planType': 'free'
        })
