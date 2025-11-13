"""
Authentication Handlers
Handles user registration, login, and JWT token verification
"""
import json
import os
import jwt
import logging
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from typing import Dict, Any, Tuple

logger = logging.getLogger(__name__)

# JWT Configuration
SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
JWT_EXPIRATION_HOURS = 24

# Import user model
try:
    from ..models.user_model import User
except ImportError:
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))
    from models.user_model import User

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

def generate_jwt(user_id: str, email: str) -> str:
    """Generate JWT token"""
    payload = {
        'userId': user_id,
        'email': email,
        'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def verify_jwt(token: str) -> Tuple[bool, Dict[str, Any]]:
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return True, payload
    except jwt.ExpiredSignatureError:
        return False, {'error': 'Token expired'}
    except jwt.InvalidTokenError:
        return False, {'error': 'Invalid token'}

def lambda_handler_register(event, context):
    """
    POST /api/auth/register
    Register a new user
    """
    try:
        # Parse request body
        body = json.loads(event.get('body', '{}'))
        email = body.get('email')
        password = body.get('password')

        # Validation
        if not email or not password:
            return create_response(400, {
                'error': 'Email and password are required'
            })

        if len(password) < 8:
            return create_response(400, {
                'error': 'Password must be at least 8 characters'
            })

        # Check if user already exists
        existing_user = User.get_by_email(email)
        if existing_user:
            return create_response(409, {
                'error': 'User with this email already exists'
            })

        # Hash password and create user
        password_hash = generate_password_hash(password)
        user = User.create(email, password_hash)

        # Generate JWT token
        token = generate_jwt(user['userId'], user['email'])

        logger.info(f"User registered successfully: {email}")

        return create_response(201, {
            'message': 'User registered successfully',
            'token': token,
            'user': {
                'userId': user['userId'],
                'email': user['email'],
                'planType': user['planType'],
                'emailsUsedThisMonth': user['emailsUsedThisMonth']
            }
        })

    except Exception as e:
        logger.error(f"Registration error: {e}")
        return create_response(500, {
            'error': 'Internal server error'
        })

def lambda_handler_login(event, context):
    """
    POST /api/auth/login
    Login user and return JWT token
    """
    try:
        # Parse request body
        body = json.loads(event.get('body', '{}'))
        email = body.get('email')
        password = body.get('password')

        # Validation
        if not email or not password:
            return create_response(400, {
                'error': 'Email and password are required'
            })

        # Get user by email
        user = User.get_by_email(email)
        if not user:
            return create_response(401, {
                'error': 'Invalid email or password'
            })

        # Verify password
        if not check_password_hash(user['passwordHash'], password):
            return create_response(401, {
                'error': 'Invalid email or password'
            })

        # Generate JWT token
        token = generate_jwt(user['userId'], user['email'])

        logger.info(f"User logged in: {email}")

        return create_response(200, {
            'message': 'Login successful',
            'token': token,
            'user': {
                'userId': user['userId'],
                'email': user['email'],
                'planType': user['planType'],
                'subscriptionStatus': user.get('subscriptionStatus', 'none'),
                'emailsUsedThisMonth': user.get('emailsUsedThisMonth', 0)
            }
        })

    except Exception as e:
        logger.error(f"Login error: {e}")
        return create_response(500, {
            'error': 'Internal server error'
        })

def lambda_handler_verify(event, context):
    """
    GET /api/auth/verify
    Verify JWT token and return user info
    """
    try:
        # Get token from Authorization header
        auth_header = event.get('headers', {}).get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return create_response(401, {
                'error': 'Invalid authorization header'
            })

        token = auth_header.replace('Bearer ', '')

        # Verify token
        valid, payload = verify_jwt(token)
        if not valid:
            return create_response(401, payload)

        # Get user info
        user = User.get_by_id(payload['userId'])
        if not user:
            return create_response(404, {
                'error': 'User not found'
            })

        return create_response(200, {
            'valid': True,
            'user': {
                'userId': user['userId'],
                'email': user['email'],
                'planType': user['planType'],
                'subscriptionStatus': user.get('subscriptionStatus', 'none'),
                'emailsUsedThisMonth': user.get('emailsUsedThisMonth', 0),
                'stripeCustomerId': user.get('stripeCustomerId')
            }
        })

    except Exception as e:
        logger.error(f"Verification error: {e}")
        return create_response(500, {
            'error': 'Internal server error'
        })

def lambda_handler_get_usage(event, context):
    """
    GET /api/auth/usage
    Get user's current usage and quota
    """
    try:
        # Get token from Authorization header
        auth_header = event.get('headers', {}).get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return create_response(401, {
                'error': 'Invalid authorization header'
            })

        token = auth_header.replace('Bearer ', '')

        # Verify token
        valid, payload = verify_jwt(token)
        if not valid:
            return create_response(401, payload)

        # Check quota
        quota_info = User.check_quota(payload['userId'])

        return create_response(200, quota_info)

    except Exception as e:
        logger.error(f"Usage check error: {e}")
        return create_response(500, {
            'error': 'Internal server error'
        })

# Main Lambda handlers for AWS
def register_handler(event, context):
    """AWS Lambda entry point for registration"""
    return lambda_handler_register(event, context)

def login_handler(event, context):
    """AWS Lambda entry point for login"""
    return lambda_handler_login(event, context)

def verify_handler(event, context):
    """AWS Lambda entry point for token verification"""
    return lambda_handler_verify(event, context)

def usage_handler(event, context):
    """AWS Lambda entry point for usage check"""
    return lambda_handler_get_usage(event, context)
