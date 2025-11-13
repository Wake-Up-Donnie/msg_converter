"""
Auto-selecting database module.
Automatically chooses between SQLite (local) and DynamoDB (AWS) based on environment.

Usage:
    # Replace 'import models' with 'import models_auto as models'
    # Or import specific functions:
    from models_auto import get_user_by_email, create_user, init_db

The module detects the environment and imports the appropriate backend:
- Local development (no USERS_TABLE env var): Uses SQLite via models.py
- AWS Lambda (USERS_TABLE env var set): Uses DynamoDB via models_dynamodb.py
"""

import os
import logging

logger = logging.getLogger(__name__)

# Detect which database backend to use
USE_DYNAMODB = bool(os.environ.get('USERS_TABLE')) or bool(os.environ.get('AWS_EXECUTION_ENV'))

if USE_DYNAMODB:
    logger.info("Using DynamoDB for user storage")
    from models_dynamodb import (
        User,
        init_db,
        create_user,
        get_user_by_email,
        get_user_by_id,
        seed_unlimited_user,
        update_user_subscription,
        increment_conversion_count,
        can_user_convert
    )
else:
    logger.info("Using SQLite for user storage (local development)")
    from models import (
        User,
        init_db,
        create_user,
        get_user_by_email,
        get_user_by_id,
        seed_unlimited_user
    )

    # Add compatibility functions for DynamoDB-specific features
    def update_user_subscription(email: str, subscription_status: str,
                                 is_unlimited: bool = False,
                                 stripe_customer_id: str = None,
                                 stripe_subscription_id: str = None) -> bool:
        """Compatibility stub for SQLite - not fully implemented"""
        logger.warning("update_user_subscription not fully implemented for SQLite backend")
        return False

    def increment_conversion_count(email: str) -> bool:
        """Compatibility stub for SQLite - not fully implemented"""
        logger.warning("increment_conversion_count not fully implemented for SQLite backend")
        return False

    def can_user_convert(email: str, free_limit: int = 5) -> tuple[bool, str]:
        """Compatibility stub for SQLite - not fully implemented"""
        user = get_user_by_email(email)
        if not user:
            return False, "User not found"
        if user.is_unlimited:
            return True, "Unlimited access"
        if user.subscription_status == 'active':
            return True, "Active subscription"
        if user.free_conversions_used < free_limit:
            return True, f"Free tier ({user.free_conversions_used}/{free_limit} used)"
        return False, f"Free tier limit exceeded ({free_limit} conversions)"


# Export the database type for logging/debugging
DATABASE_TYPE = "DynamoDB" if USE_DYNAMODB else "SQLite"

__all__ = [
    'User',
    'init_db',
    'create_user',
    'get_user_by_email',
    'get_user_by_id',
    'seed_unlimited_user',
    'update_user_subscription',
    'increment_conversion_count',
    'can_user_convert',
    'DATABASE_TYPE',
    'USE_DYNAMODB'
]
