"""
DynamoDB-based user management for AWS deployment.
This module provides the same interface as models.py but uses DynamoDB instead of SQLite.
"""

import os
import uuid
import logging
from datetime import datetime
from dataclasses import dataclass
from typing import Optional
from werkzeug.security import generate_password_hash, check_password_hash
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# DynamoDB configuration
USERS_TABLE = os.environ.get('USERS_TABLE', 'eml-converter-users-prod')
AWS_REGION = os.environ.get('AWS_REGION_NAME') or os.environ.get('AWS_REGION', 'us-east-1')

# Initialize DynamoDB client
try:
    dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
    users_table = dynamodb.Table(USERS_TABLE)
    logger.info(f"DynamoDB initialized: table={USERS_TABLE}, region={AWS_REGION}")
except Exception as e:
    logger.error(f"Failed to initialize DynamoDB: {e}")
    dynamodb = None
    users_table = None


@dataclass
class User:
    """User data class matching SQLite version for compatibility"""
    id: Optional[str]  # user_id in DynamoDB
    email: str
    password_hash: str
    subscription_status: Optional[str] = None
    is_unlimited: bool = False
    free_conversions_used: int = 0
    created_at: Optional[str] = None
    stripe_customer_id: Optional[str] = None
    stripe_subscription_id: Optional[str] = None


def init_db():
    """
    Initialize database - for DynamoDB this is a no-op as table is created via CloudFormation.
    Kept for compatibility with SQLite version.
    """
    if users_table is None:
        logger.warning("DynamoDB table not initialized")
        return False

    try:
        # Just check if table exists
        users_table.table_status
        logger.info(f"DynamoDB table '{USERS_TABLE}' is ready")
        return True
    except Exception as e:
        logger.error(f"DynamoDB table check failed: {e}")
        return False


def create_user(email: str, password_hash: str) -> Optional[User]:
    """
    Create a new user in DynamoDB.

    Args:
        email: User's email address (primary key)
        password_hash: Hashed password

    Returns:
        User object or None if creation fails
    """
    if users_table is None:
        logger.error("DynamoDB table not initialized")
        return None

    user_id = str(uuid.uuid4())
    created_at = datetime.utcnow().isoformat() + 'Z'

    user_item = {
        'email': email,
        'user_id': user_id,
        'password_hash': password_hash,
        'subscription_status': None,
        'is_unlimited': False,
        'free_conversions_used': 0,
        'stripe_customer_id': None,
        'stripe_subscription_id': None,
        'created_at': created_at,
        'updated_at': created_at
    }

    try:
        # Use ConditionExpression to prevent duplicate emails
        users_table.put_item(
            Item=user_item,
            ConditionExpression='attribute_not_exists(email)'
        )
        logger.info(f"Created user: {email}")

        return User(
            id=user_id,
            email=email,
            password_hash=password_hash,
            subscription_status=None,
            is_unlimited=False,
            free_conversions_used=0,
            created_at=created_at
        )

    except ClientError as e:
        if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
            logger.warning(f"User already exists: {email}")
        else:
            logger.error(f"Error creating user: {e}")
        return None


def get_user_by_email(email: str) -> Optional[User]:
    """
    Retrieve a user by email address.

    Args:
        email: User's email address

    Returns:
        User object or None if not found
    """
    if users_table is None:
        logger.error("DynamoDB table not initialized")
        return None

    try:
        response = users_table.get_item(Key={'email': email})

        if 'Item' not in response:
            logger.debug(f"User not found: {email}")
            return None

        item = response['Item']
        return User(
            id=item.get('user_id'),
            email=item['email'],
            password_hash=item['password_hash'],
            subscription_status=item.get('subscription_status'),
            is_unlimited=bool(item.get('is_unlimited', False)),
            free_conversions_used=int(item.get('free_conversions_used', 0)),
            created_at=item.get('created_at'),
            stripe_customer_id=item.get('stripe_customer_id'),
            stripe_subscription_id=item.get('stripe_subscription_id')
        )

    except ClientError as e:
        logger.error(f"Error getting user by email: {e}")
        return None


def get_user_by_id(user_id: str) -> Optional[User]:
    """
    Retrieve a user by user_id using the Global Secondary Index.

    Args:
        user_id: User's unique ID

    Returns:
        User object or None if not found
    """
    if users_table is None:
        logger.error("DynamoDB table not initialized")
        return None

    try:
        response = users_table.query(
            IndexName='UserIdIndex',
            KeyConditionExpression='user_id = :uid',
            ExpressionAttributeValues={':uid': user_id}
        )

        if not response.get('Items'):
            logger.debug(f"User not found by ID: {user_id}")
            return None

        item = response['Items'][0]
        return User(
            id=item.get('user_id'),
            email=item['email'],
            password_hash=item['password_hash'],
            subscription_status=item.get('subscription_status'),
            is_unlimited=bool(item.get('is_unlimited', False)),
            free_conversions_used=int(item.get('free_conversions_used', 0)),
            created_at=item.get('created_at'),
            stripe_customer_id=item.get('stripe_customer_id'),
            stripe_subscription_id=item.get('stripe_subscription_id')
        )

    except ClientError as e:
        logger.error(f"Error getting user by ID: {e}")
        return None


def update_user_subscription(email: str, subscription_status: str,
                             is_unlimited: bool = False,
                             stripe_customer_id: str = None,
                             stripe_subscription_id: str = None) -> bool:
    """
    Update user subscription information.

    Args:
        email: User's email address
        subscription_status: New subscription status (active, inactive, cancelled, etc.)
        is_unlimited: Whether user has unlimited access
        stripe_customer_id: Stripe customer ID
        stripe_subscription_id: Stripe subscription ID

    Returns:
        True if update successful, False otherwise
    """
    if users_table is None:
        logger.error("DynamoDB table not initialized")
        return False

    try:
        update_expr = "SET subscription_status = :status, is_unlimited = :unlimited, updated_at = :updated"
        expr_values = {
            ':status': subscription_status,
            ':unlimited': is_unlimited,
            ':updated': datetime.utcnow().isoformat() + 'Z'
        }

        if stripe_customer_id is not None:
            update_expr += ", stripe_customer_id = :cust_id"
            expr_values[':cust_id'] = stripe_customer_id

        if stripe_subscription_id is not None:
            update_expr += ", stripe_subscription_id = :sub_id"
            expr_values[':sub_id'] = stripe_subscription_id

        users_table.update_item(
            Key={'email': email},
            UpdateExpression=update_expr,
            ExpressionAttributeValues=expr_values
        )

        logger.info(f"Updated subscription for user: {email}")
        return True

    except ClientError as e:
        logger.error(f"Error updating user subscription: {e}")
        return False


def increment_conversion_count(email: str) -> bool:
    """
    Increment the free conversions used counter for a user.

    Args:
        email: User's email address

    Returns:
        True if increment successful, False otherwise
    """
    if users_table is None:
        logger.error("DynamoDB table not initialized")
        return False

    try:
        users_table.update_item(
            Key={'email': email},
            UpdateExpression='SET free_conversions_used = free_conversions_used + :inc, updated_at = :updated',
            ExpressionAttributeValues={
                ':inc': 1,
                ':updated': datetime.utcnow().isoformat() + 'Z'
            }
        )

        logger.debug(f"Incremented conversion count for user: {email}")
        return True

    except ClientError as e:
        logger.error(f"Error incrementing conversion count: {e}")
        return False


def can_user_convert(email: str, free_limit: int = 5) -> tuple[bool, str]:
    """
    Check if a user can perform a conversion based on their subscription and usage.

    Args:
        email: User's email address
        free_limit: Maximum number of free conversions allowed

    Returns:
        Tuple of (can_convert: bool, reason: str)
    """
    user = get_user_by_email(email)

    if not user:
        return False, "User not found"

    # Unlimited users can always convert
    if user.is_unlimited:
        return True, "Unlimited access"

    # Active subscription users can convert
    if user.subscription_status == 'active':
        return True, "Active subscription"

    # Check free tier limit
    if user.free_conversions_used < free_limit:
        return True, f"Free tier ({user.free_conversions_used}/{free_limit} used)"

    return False, f"Free tier limit exceeded ({free_limit} conversions)"


def seed_unlimited_user():
    """
    Seed a default unlimited user for testing.
    Compatible with SQLite version but uses DynamoDB.
    """
    import secrets
    email = "unlimited@example.com"

    # Check if user exists
    if get_user_by_email(email):
        logger.info(f"Unlimited user already exists: {email}")
        return

    # Create user
    password = secrets.token_urlsafe(12)
    password_hash = generate_password_hash(password)

    user_id = str(uuid.uuid4())
    created_at = datetime.utcnow().isoformat() + 'Z'

    try:
        users_table.put_item(
            Item={
                'email': email,
                'user_id': user_id,
                'password_hash': password_hash,
                'subscription_status': 'active',
                'is_unlimited': True,
                'free_conversions_used': 0,
                'stripe_customer_id': None,
                'stripe_subscription_id': None,
                'created_at': created_at,
                'updated_at': created_at
            }
        )

        logger.info(f"Seeded unlimited user '{email}' with password: {password}")

    except ClientError as e:
        logger.error(f"Error seeding unlimited user: {e}")
