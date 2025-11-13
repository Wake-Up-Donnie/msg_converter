#!/usr/bin/env python3
"""
Script to create users in DynamoDB with free unlimited access.
This script can be run locally or in AWS to manage users.

Usage:
    python add_user_to_dynamodb.py --email user@example.com [--password PASSWORD] [--environment prod]

Environment Variables Required:
    AWS_REGION or AWS_DEFAULT_REGION (default: us-east-1)
    Or specify --region flag
"""

import os
import sys
import argparse
import secrets
import uuid
from datetime import datetime
from werkzeug.security import generate_password_hash
import boto3
from botocore.exceptions import ClientError

def get_table_name(environment='prod'):
    """
    Get the DynamoDB table name for the given environment.
    """
    # Try to get from CloudFormation stack outputs
    stack_name = f'eml-converter-{environment}'
    table_name = f'eml-converter-users-{environment}'
    return table_name


def create_dynamodb_user(
    email: str,
    password: str = None,
    environment: str = 'prod',
    region: str = None
):
    """
    Create a user in DynamoDB with unlimited access.

    Args:
        email: User's email address
        password: Password (will be hashed). If None, generates random password
        environment: Environment (dev/staging/prod)
        region: AWS region (defaults to us-east-1 or AWS_REGION env var)

    Returns:
        dict: Created user item
    """
    # Set up AWS region
    if region is None:
        region = os.environ.get('AWS_REGION') or os.environ.get('AWS_DEFAULT_REGION') or 'us-east-1'

    # Initialize DynamoDB
    dynamodb = boto3.resource('dynamodb', region_name=region)
    table_name = get_table_name(environment)

    try:
        table = dynamodb.Table(table_name)
    except Exception as e:
        print(f"❌ Error connecting to DynamoDB table '{table_name}'")
        print(f"   Make sure the table exists and you have proper AWS credentials configured.")
        print(f"   Error: {e}")
        return None

    # Generate password if not provided
    if password is None:
        password = secrets.token_urlsafe(16)

    # Hash the password
    password_hash = generate_password_hash(password)

    # Generate user ID
    user_id = str(uuid.uuid4())

    # Create timestamp
    created_at = datetime.utcnow().isoformat() + 'Z'

    # Prepare user item
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
        'updated_at': created_at
    }

    # Check if user already exists
    try:
        response = table.get_item(Key={'email': email})
        if 'Item' in response:
            print(f"❌ User with email '{email}' already exists in DynamoDB table '{table_name}'")
            print(f"   User ID: {response['Item'].get('user_id')}")
            print(f"   Subscription Status: {response['Item'].get('subscription_status')}")
            print(f"   Unlimited Access: {response['Item'].get('is_unlimited')}")
            print("\n   To update this user, delete them first or use a different email.")
            return None
    except ClientError as e:
        print(f"❌ Error checking for existing user: {e}")
        return None

    # Add user to DynamoDB
    try:
        table.put_item(Item=user_item)
        print("✅ User created successfully in DynamoDB!")
        print(f"   Environment: {environment}")
        print(f"   Table: {table_name}")
        print(f"   Region: {region}")
        print(f"   User ID: {user_id}")
        print(f"   Email: {email}")
        print(f"   Password: {password}")
        print(f"   Subscription Status: active")
        print(f"   Unlimited Access: Yes (Free Forever)")
        print(f"   Created At: {created_at}")
        print("\n⚠️  IMPORTANT: Save the password - it cannot be retrieved later!")

        return {
            'user_id': user_id,
            'email': email,
            'password': password,
            'table_name': table_name,
            'region': region
        }

    except ClientError as e:
        print(f"❌ Error creating user in DynamoDB: {e}")
        return None


def verify_user(email: str, environment: str = 'prod', region: str = None):
    """
    Verify a user exists in DynamoDB and display their details.
    """
    if region is None:
        region = os.environ.get('AWS_REGION') or os.environ.get('AWS_DEFAULT_REGION') or 'us-east-1'

    dynamodb = boto3.resource('dynamodb', region_name=region)
    table_name = get_table_name(environment)

    try:
        table = dynamodb.Table(table_name)
        response = table.get_item(Key={'email': email})

        if 'Item' in response:
            user = response['Item']
            print("✅ User found in DynamoDB:")
            print(f"   User ID: {user.get('user_id')}")
            print(f"   Email: {user.get('email')}")
            print(f"   Subscription Status: {user.get('subscription_status')}")
            print(f"   Unlimited Access: {user.get('is_unlimited')}")
            print(f"   Free Conversions Used: {user.get('free_conversions_used')}")
            print(f"   Created At: {user.get('created_at')}")
            if user.get('stripe_customer_id'):
                print(f"   Stripe Customer ID: {user.get('stripe_customer_id')}")
            if user.get('stripe_subscription_id'):
                print(f"   Stripe Subscription ID: {user.get('stripe_subscription_id')}")
            return user
        else:
            print(f"❌ User with email '{email}' not found in DynamoDB table '{table_name}'")
            return None

    except ClientError as e:
        print(f"❌ Error verifying user: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description='Create or verify users in DynamoDB with free unlimited access'
    )
    parser.add_argument('--email', required=True, help='User email address')
    parser.add_argument('--password', help='User password (optional, will generate random if not provided)')
    parser.add_argument('--environment', default='prod', choices=['dev', 'staging', 'prod'],
                        help='Environment (default: prod)')
    parser.add_argument('--region', help='AWS region (default: from AWS_REGION env var or us-east-1)')
    parser.add_argument('--verify', action='store_true', help='Verify user exists instead of creating')

    args = parser.parse_args()

    if args.verify:
        print(f"Verifying user in DynamoDB...")
        print(f"Email: {args.email}")
        print(f"Environment: {args.environment}\n")
        verify_user(args.email, args.environment, args.region)
    else:
        print(f"Creating user with free unlimited access in DynamoDB...")
        print(f"Email: {args.email}")
        print(f"Environment: {args.environment}\n")

        result = create_dynamodb_user(
            email=args.email,
            password=args.password,
            environment=args.environment,
            region=args.region
        )

        if result:
            print("\n" + "="*60)
            print("User can now log in with the credentials above.")
            print("The user data is stored in DynamoDB and will persist across")
            print("Lambda invocations and deployments.")
            print("="*60)


if __name__ == "__main__":
    main()
