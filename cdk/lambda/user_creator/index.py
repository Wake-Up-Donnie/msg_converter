"""
Custom Resource Lambda to create whitelisted users in DynamoDB.

This Lambda is triggered during CDK deployment to automatically create
users with free unlimited access based on the whitelist configuration.
"""

import json
import os
import uuid
import secrets
import boto3
import logging
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource('dynamodb')
table_name = os.environ['USERS_TABLE']
table = dynamodb.Table(table_name)


def generate_password_hash(password: str) -> str:
    """
    Generate bcrypt-style password hash.
    For production, this would use werkzeug.security or bcrypt library.
    For simplicity in Lambda layer-less deployment, we'll use a basic hash.
    Note: In production, ensure werkzeug is included in Lambda layer or container.
    """
    try:
        from werkzeug.security import generate_password_hash as werkzeug_hash
        return werkzeug_hash(password)
    except ImportError:
        # Fallback: Use hashlib (NOT secure for production, just for demo)
        import hashlib
        logger.warning("werkzeug not available, using fallback hash (NOT SECURE)")
        return f"sha256${hashlib.sha256(password.encode()).hexdigest()}"


def create_user(email: str, name: str = "", notes: str = "") -> dict:
    """
    Create a user in DynamoDB with free unlimited access.

    Args:
        email: User's email address
        name: User's display name (optional)
        notes: Additional notes (optional)

    Returns:
        dict: Created user details including generated password
    """
    # Generate random password
    password = secrets.token_urlsafe(16)
    password_hash = generate_password_hash(password)

    user_id = str(uuid.uuid4())
    created_at = datetime.utcnow().isoformat() + 'Z'

    user_item = {
        'email': email,
        'user_id': user_id,
        'password_hash': password_hash,
        'subscription_status': 'active',
        'is_unlimited': True,
        'free_conversions_used': 0,
        'stripe_customer_id': None,
        'stripe_subscription_id': None,
        'created_at': created_at,
        'updated_at': created_at,
        'name': name,
        'notes': notes
    }

    # Check if user exists
    try:
        response = table.get_item(Key={'email': email})
        if 'Item' in response:
            logger.info(f"User already exists: {email}")
            return {
                'email': email,
                'status': 'already_exists',
                'user_id': response['Item'].get('user_id')
            }
    except Exception as e:
        logger.error(f"Error checking for existing user: {e}")

    # Create new user
    try:
        table.put_item(
            Item=user_item,
            ConditionExpression='attribute_not_exists(email)'
        )

        logger.info(f"Created user: {email}")
        logger.info(f"Password for {email}: {password}")

        return {
            'email': email,
            'user_id': user_id,
            'password': password,
            'status': 'created',
            'subscription_status': 'active',
            'is_unlimited': True
        }

    except dynamodb.meta.client.exceptions.ConditionalCheckFailedException:
        logger.warning(f"User already exists (race condition): {email}")
        return {
            'email': email,
            'status': 'already_exists'
        }
    except Exception as e:
        logger.error(f"Error creating user {email}: {e}")
        return {
            'email': email,
            'status': 'error',
            'error': str(e)
        }


def handler(event, context):
    """
    CloudFormation Custom Resource handler.

    Handles Create, Update, and Delete events for whitelisted users.
    """
    logger.info(f"Event: {json.dumps(event)}")

    request_type = event['RequestType']
    properties = event.get('ResourceProperties', {})

    try:
        whitelisted_emails_json = properties.get('WhitelistedEmails', '[]')
        whitelisted_emails = json.loads(whitelisted_emails_json)

        if request_type in ['Create', 'Update']:
            logger.info(f"Processing {len(whitelisted_emails)} whitelisted users")

            results = []
            passwords = {}

            for user_config in whitelisted_emails:
                if isinstance(user_config, dict):
                    email = user_config.get('email')
                    name = user_config.get('name', '')
                    notes = user_config.get('notes', '')
                else:
                    # Simple string format
                    email = user_config
                    name = ''
                    notes = ''

                if not email:
                    continue

                result = create_user(email, name, notes)
                results.append(result)

                # Store password for output (only for newly created users)
                if result.get('status') == 'created' and result.get('password'):
                    passwords[email] = result['password']

            # Log passwords for created users
            if passwords:
                logger.info("=" * 60)
                logger.info("WHITELISTED USER CREDENTIALS:")
                logger.info("=" * 60)
                for email, password in passwords.items():
                    logger.info(f"Email: {email}")
                    logger.info(f"Password: {password}")
                    logger.info(f"Access: Unlimited (Free Forever)")
                    logger.info("-" * 60)
                logger.info("IMPORTANT: Save these passwords - they cannot be retrieved later!")
                logger.info("=" * 60)

            return {
                'PhysicalResourceId': f"WhitelistedUsers-{properties.get('Environment', 'prod')}",
                'Data': {
                    'UsersCreated': len([r for r in results if r.get('status') == 'created']),
                    'UsersExisting': len([r for r in results if r.get('status') == 'already_exists']),
                    'TotalUsers': len(results),
                    'Message': f"Processed {len(results)} whitelisted users. Check CloudWatch Logs for passwords."
                }
            }

        elif request_type == 'Delete':
            # On stack deletion, we don't delete users (they should persist)
            logger.info("Delete event - users will be retained in DynamoDB")
            return {
                'PhysicalResourceId': event.get('PhysicalResourceId', 'WhitelistedUsers'),
                'Data': {
                    'Message': 'Users retained in DynamoDB'
                }
            }

    except Exception as e:
        logger.error(f"Error processing custom resource: {e}", exc_info=True)
        # Don't fail the CloudFormation deployment
        return {
            'PhysicalResourceId': event.get('PhysicalResourceId', 'WhitelistedUsers-Error'),
            'Data': {
                'Error': str(e),
                'Message': 'Failed to process whitelisted users - check CloudWatch Logs'
            }
        }
