# Java Implementation Guide: Stripe Subscription Landing Page with AWS

This document provides a comprehensive guide for implementing a Stripe subscription system with AWS infrastructure, originally built in Python/Flask, adapted for Java/Spring Boot applications.

## Table of Contents
1. [Original Python Implementation Overview](#original-python-implementation-overview)
2. [Stripe Integration Architecture](#stripe-integration-architecture)
3. [AWS Infrastructure Setup](#aws-infrastructure-setup)
4. [Java Migration Guide](#java-migration-guide)
5. [Complete Java Implementation](#complete-java-implementation)
6. [Deployment Guide](#deployment-guide)

---

## Original Python Implementation Overview

### Technology Stack
- **Backend**: Python 3.12 + Flask
- **Frontend**: React.js
- **Authentication**: JWT tokens
- **Payment Processing**: Stripe API
- **Database**: AWS DynamoDB
- **Infrastructure**: AWS SAM/CloudFormation
- **Hosting**:
  - Backend: AWS Lambda + API Gateway
  - Frontend: S3 + CloudFront
  - Database: DynamoDB

### Architecture Flow
```
User → CloudFront → S3 (React App)
        ↓
User → CloudFront → API Gateway → Lambda Functions → DynamoDB
                                        ↓
                                  Stripe API
```

### Key Features Implemented
1. User registration and login (JWT-based)
2. Free tier with usage limits (5 conversions/month)
3. Stripe checkout for subscriptions (monthly/yearly)
4. Webhook handling for subscription events
5. Customer portal for subscription management
6. Usage tracking and quota enforcement

---

## Stripe Integration Architecture

### 1. Stripe Products and Prices Setup

**Created Products:**
- **EML Converter - Monthly**: Unlimited email conversions for $10/month
- **EML Converter - Yearly**: Unlimited email conversions for $80/year (save $40)

**Python Implementation** (`stripe-setup/setup_stripe_products.py`):
```python
import stripe
import os

stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')

# Create Monthly Product
monthly_product = stripe.Product.create(
    name="EML Converter - Monthly",
    description="Unlimited email conversions for $10/month",
    metadata={
        "plan_type": "monthly",
        "email_limit": "unlimited"
    }
)

# Create Monthly Price
monthly_price = stripe.Price.create(
    product=monthly_product.id,
    unit_amount=1000,  # $10.00 in cents
    currency="usd",
    recurring={
        "interval": "month",
        "interval_count": 1
    },
    metadata={
        "plan_type": "monthly"
    }
)

# Create Yearly Product
yearly_product = stripe.Product.create(
    name="EML Converter - Yearly",
    description="Unlimited email conversions for $80/year (Save $40!)",
    metadata={
        "plan_type": "yearly",
        "email_limit": "unlimited"
    }
)

# Create Yearly Price
yearly_price = stripe.Price.create(
    product=yearly_product.id,
    unit_amount=8000,  # $80.00 in cents
    currency="usd",
    recurring={
        "interval": "year",
        "interval_count": 1
    },
    metadata={
        "plan_type": "yearly"
    }
)
```

### 2. Webhook Configuration

**Automated Webhook Setup** (`stripe-setup/configure_webhook.py`):
```python
import stripe

# Create webhook endpoint
webhook_endpoint = stripe.WebhookEndpoint.create(
    url="https://your-api-gateway.amazonaws.com/dev/api/stripe/webhook",
    enabled_events=[
        'checkout.session.completed',
        'customer.subscription.created',
        'customer.subscription.updated',
        'customer.subscription.deleted',
        'invoice.payment_succeeded',
        'invoice.payment_failed',
    ],
    description="EML Converter Subscription Webhook - dev",
)

webhook_secret = webhook_endpoint.secret  # Used to verify webhook signatures
```

**Events Handled:**
- `checkout.session.completed`: User completes checkout, activate subscription
- `customer.subscription.created`: New subscription created
- `customer.subscription.updated`: Plan change or renewal
- `customer.subscription.deleted`: Cancellation
- `invoice.payment_succeeded`: Successful recurring payment
- `invoice.payment_failed`: Failed payment (downgrade to free tier)

### 3. User Authentication Flow

**Registration:**
```python
import jwt
import bcrypt
from datetime import datetime, timedelta

def register_handler(event, context):
    body = json.loads(event['body'])
    email = body['email']
    password = body['password']

    # Hash password
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Create user in DynamoDB
    user = {
        'userId': str(uuid.uuid4()),
        'email': email,
        'passwordHash': password_hash.decode('utf-8'),
        'subscriptionStatus': 'free',
        'usageCount': 0,
        'usageLimit': 5,
        'createdAt': datetime.utcnow().isoformat()
    }

    dynamodb.put_item(TableName='subscription-users-dev', Item=user)

    # Generate JWT token
    token = jwt.encode({
        'userId': user['userId'],
        'email': email,
        'exp': datetime.utcnow() + timedelta(days=7)
    }, SECRET_KEY, algorithm='HS256')

    return {
        'statusCode': 200,
        'body': json.dumps({'token': token, 'user': user})
    }
```

**Login:**
```python
def login_handler(event, context):
    body = json.loads(event['body'])
    email = body['email']
    password = body['password']

    # Find user by email
    response = dynamodb.query(
        TableName='subscription-users-dev',
        IndexName='EmailIndex',
        KeyConditionExpression='email = :email',
        ExpressionAttributeValues={':email': {'S': email}}
    )

    if not response['Items']:
        return {'statusCode': 401, 'body': json.dumps({'error': 'Invalid credentials'})}

    user = response['Items'][0]

    # Verify password
    if bcrypt.checkpw(password.encode('utf-8'), user['passwordHash'].encode('utf-8')):
        token = jwt.encode({
            'userId': user['userId'],
            'email': email,
            'exp': datetime.utcnow() + timedelta(days=7)
        }, SECRET_KEY, algorithm='HS256')

        return {
            'statusCode': 200,
            'body': json.dumps({'token': token, 'user': user})
        }

    return {'statusCode': 401, 'body': json.dumps({'error': 'Invalid credentials'})}
```

### 4. Stripe Checkout Session Creation

```python
def checkout_handler(event, context):
    body = json.loads(event['body'])
    price_id = body['priceId']  # monthly_price_id or yearly_price_id

    # Get user from JWT token
    token = event['headers'].get('Authorization', '').replace('Bearer ', '')
    payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    user_id = payload['userId']

    # Create Stripe checkout session
    checkout_session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[{
            'price': price_id,
            'quantity': 1,
        }],
        mode='subscription',
        success_url=f"{FRONTEND_URL}/dashboard?session_id={{CHECKOUT_SESSION_ID}}",
        cancel_url=f"{FRONTEND_URL}/pricing",
        metadata={
            'userId': user_id
        },
        client_reference_id=user_id,
    )

    return {
        'statusCode': 200,
        'body': json.dumps({'sessionId': checkout_session.id})
    }
```

### 5. Webhook Handler

```python
def webhook_handler(event, context):
    payload = event['body']
    sig_header = event['headers'].get('Stripe-Signature')

    try:
        # Verify webhook signature
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        return {'statusCode': 400}
    except stripe.error.SignatureVerificationError:
        return {'statusCode': 400}

    # Handle the event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        user_id = session['metadata']['userId']
        subscription_id = session['subscription']
        customer_id = session['customer']

        # Update user in DynamoDB
        dynamodb.update_item(
            TableName='subscription-users-dev',
            Key={'userId': {'S': user_id}},
            UpdateExpression='SET subscriptionStatus = :status, stripeCustomerId = :customerId, stripeSubscriptionId = :subscriptionId, usageLimit = :limit',
            ExpressionAttributeValues={
                ':status': {'S': 'active'},
                ':customerId': {'S': customer_id},
                ':subscriptionId': {'S': subscription_id},
                ':limit': {'N': '-1'}  # Unlimited
            }
        )

    elif event['type'] == 'customer.subscription.deleted':
        subscription = event['data']['object']
        customer_id = subscription['customer']

        # Find user by customer ID and downgrade to free tier
        # ... implementation

    return {'statusCode': 200}
```

### 6. Customer Portal Session

```python
def portal_handler(event, context):
    # Get user from JWT token
    token = event['headers'].get('Authorization', '').replace('Bearer ', '')
    payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    user_id = payload['userId']

    # Get user's Stripe customer ID
    response = dynamodb.get_item(
        TableName='subscription-users-dev',
        Key={'userId': {'S': user_id}}
    )

    customer_id = response['Item']['stripeCustomerId']['S']

    # Create portal session
    portal_session = stripe.billing_portal.Session.create(
        customer=customer_id,
        return_url=f"{FRONTEND_URL}/dashboard",
    )

    return {
        'statusCode': 200,
        'body': json.dumps({'url': portal_session.url})
    }
```

---

## AWS Infrastructure Setup

### CloudFormation Template Structure

**Key Resources Created:**

1. **DynamoDB Table** (`subscription-users-{env}`):
```yaml
UsersTable:
  Type: AWS::DynamoDB::Table
  Properties:
    TableName: !Sub 'subscription-users-${Environment}'
    BillingMode: PAY_PER_REQUEST
    AttributeDefinitions:
      - AttributeName: userId
        AttributeType: S
      - AttributeName: email
        AttributeType: S
    KeySchema:
      - AttributeName: userId
        KeyType: HASH
    GlobalSecondaryIndexes:
      - IndexName: EmailIndex
        KeySchema:
          - AttributeName: email
            KeyType: HASH
        Projection:
          ProjectionType: ALL
```

**User Schema:**
```json
{
  "userId": "uuid-v4",
  "email": "user@example.com",
  "passwordHash": "bcrypt-hash",
  "subscriptionStatus": "free|active|cancelled",
  "usageCount": 0,
  "usageLimit": 5,
  "stripeCustomerId": "cus_xxx",
  "stripeSubscriptionId": "sub_xxx",
  "createdAt": "2025-01-01T00:00:00Z"
}
```

2. **Lambda Functions** (7 total):
   - `landing-register-{env}`: User registration
   - `landing-login-{env}`: User login
   - `landing-verify-{env}`: JWT token verification
   - `landing-usage-{env}`: Check user quota
   - `landing-checkout-{env}`: Create Stripe checkout session
   - `landing-webhook-{env}`: Handle Stripe webhooks
   - `landing-portal-{env}`: Create customer portal session

3. **API Gateway**:
```yaml
LandingPageAPI:
  Type: AWS::Serverless::Api
  Properties:
    Name: !Sub 'subscription-landing-api-${Environment}'
    StageName: !Ref Environment
    Cors:
      AllowMethods: "'DELETE,GET,HEAD,OPTIONS,PATCH,POST,PUT'"
      AllowHeaders: "'Content-Type,Authorization,Stripe-Signature'"
      AllowOrigin: "'*'"
```

**API Routes:**
- `POST /api/auth/register`: Register new user
- `POST /api/auth/login`: Login existing user
- `GET /api/auth/verify`: Verify JWT token
- `GET /api/auth/usage`: Get user usage stats
- `POST /api/stripe/create-checkout-session`: Start checkout
- `POST /api/stripe/webhook`: Receive Stripe events
- `POST /api/stripe/create-portal-session`: Customer portal

4. **S3 + CloudFront**:
```yaml
FrontendBucket:
  Type: AWS::S3::Bucket
  Properties:
    BucketName: !Sub 'subscription-landing-${Environment}-${AWS::AccountId}'
    WebsiteConfiguration:
      IndexDocument: index.html
      ErrorDocument: index.html

CloudFrontDistribution:
  Type: AWS::CloudFront::Distribution
  Properties:
    DistributionConfig:
      Origins:
        - Id: S3Origin
          DomainName: !GetAtt FrontendBucket.RegionalDomainName
        - Id: APIOrigin
          DomainName: !Sub '${LandingPageAPI}.execute-api.${AWS::Region}.amazonaws.com'
          OriginPath: !Sub '/${Environment}'
      DefaultCacheBehavior:
        TargetOriginId: S3Origin
        ViewerProtocolPolicy: redirect-to-https
      CacheBehaviors:
        - PathPattern: '/api/*'
          TargetOriginId: APIOrigin
          ViewerProtocolPolicy: redirect-to-https
          MinTTL: 0
          DefaultTTL: 0
          MaxTTL: 0
```

### Environment Variables Configuration

**Lambda Environment Variables:**
```bash
ENVIRONMENT=dev
USERS_TABLE=subscription-users-dev
STRIPE_SECRET_KEY=sk_test_xxx
STRIPE_WEBHOOK_SECRET=whsec_xxx
MONTHLY_PRICE_ID=price_xxx
YEARLY_PRICE_ID=price_xxx
SECRET_KEY=jwt-secret-key
FRONTEND_URL=https://dxxxxx.cloudfront.net
```

### Deployment Process

**Step-by-step:**
1. Setup Stripe products/prices
2. Deploy infrastructure with SAM
3. Build and deploy React frontend
4. Configure Stripe webhook
5. Update Lambda with webhook secret

**Deployment Script** (`deploy-landing-page.sh`):
```bash
#!/bin/bash
ENVIRONMENT="dev"
REGION="us-east-1"
STACK_NAME="subscription-landing-${ENVIRONMENT}"

# Step 1: Setup Stripe products
cd stripe-setup
python3 setup_stripe_products.py
cd ..

# Step 2: Deploy backend
sam build --template-file aws/template-landing-page.yaml
sam deploy \
    --template-file aws/template-landing-page.yaml \
    --stack-name ${STACK_NAME} \
    --parameter-overrides \
        Environment=${ENVIRONMENT} \
        StripeSecretKey="${STRIPE_SECRET_KEY}" \
        StripePublishableKey="${STRIPE_PUBLISHABLE_KEY}" \
        MonthlyPriceId="${MONTHLY_PRICE_ID}" \
        YearlyPriceId="${YEARLY_PRICE_ID}" \
        JWTSecretKey="${JWT_SECRET_KEY}" \
    --capabilities CAPABILITY_IAM \
    --region ${REGION} \
    --resolve-s3

# Step 3: Get outputs
API_URL=$(aws cloudformation describe-stacks \
    --stack-name ${STACK_NAME} \
    --query 'Stacks[0].Outputs[?OutputKey==`APIGatewayURL`].OutputValue' \
    --output text)

CLOUDFRONT_URL=$(aws cloudformation describe-stacks \
    --stack-name ${STACK_NAME} \
    --query 'Stacks[0].Outputs[?OutputKey==`CloudFrontURL`].OutputValue' \
    --output text)

# Step 4: Build and deploy frontend
cd landing-frontend
REACT_APP_API_URL="${API_URL}" \
REACT_APP_STRIPE_PUBLISHABLE_KEY="${STRIPE_PUBLISHABLE_KEY}" \
npm run build

aws s3 sync build/ s3://${FRONTEND_BUCKET}/ --delete

# Step 5: Configure webhook
cd ../stripe-setup
python3 configure_webhook.py --env ${ENVIRONMENT}
```

---

## Java Migration Guide

### Technology Stack Mapping

| Python/Flask | Java/Spring Boot |
|-------------|------------------|
| Flask | Spring Boot + Spring Web |
| boto3 (AWS SDK) | AWS SDK for Java v2 |
| stripe-python | stripe-java |
| PyJWT | java-jwt (Auth0) or jjwt (io.jsonwebtoken) |
| bcrypt | BCryptPasswordEncoder (Spring Security) |
| Python dictionaries | Java POJOs / DTOs |
| AWS Lambda Python Runtime | AWS Lambda Java Runtime |
| AWS SAM | AWS CDK (Java) or CloudFormation |

### Maven Dependencies

```xml
<dependencies>
    <!-- Spring Boot -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
        <version>3.2.0</version>
    </dependency>

    <!-- Spring Security for password hashing -->
    <dependency>
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-crypto</artifactId>
        <version>6.2.0</version>
    </dependency>

    <!-- AWS Lambda Java -->
    <dependency>
        <groupId>com.amazonaws</groupId>
        <artifactId>aws-lambda-java-core</artifactId>
        <version>1.2.3</version>
    </dependency>
    <dependency>
        <groupId>com.amazonaws</groupId>
        <artifactId>aws-lambda-java-events</artifactId>
        <version>3.11.4</version>
    </dependency>

    <!-- AWS SDK v2 for DynamoDB -->
    <dependency>
        <groupId>software.amazon.awssdk</groupId>
        <artifactId>dynamodb</artifactId>
        <version>2.21.0</version>
    </dependency>
    <dependency>
        <groupId>software.amazon.awssdk</groupId>
        <artifactId>dynamodb-enhanced</artifactId>
        <version>2.21.0</version>
    </dependency>

    <!-- Stripe Java SDK -->
    <dependency>
        <groupId>com.stripe</groupId>
        <artifactId>stripe-java</artifactId>
        <version>24.3.0</version>
    </dependency>

    <!-- JWT -->
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-api</artifactId>
        <version>0.12.3</version>
    </dependency>
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-impl</artifactId>
        <version>0.12.3</version>
        <scope>runtime</scope>
    </dependency>
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-jackson</artifactId>
        <version>0.12.3</version>
        <scope>runtime</scope>
    </dependency>

    <!-- JSON processing -->
    <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
        <version>2.16.0</version>
    </dependency>

    <!-- Lombok (optional, for reducing boilerplate) -->
    <dependency>
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
        <version>1.18.30</version>
        <scope>provided</scope>
    </dependency>
</dependencies>
```

### Gradle Alternative

```gradle
dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-web:3.2.0'
    implementation 'org.springframework.security:spring-security-crypto:6.2.0'
    implementation 'com.amazonaws:aws-lambda-java-core:1.2.3'
    implementation 'com.amazonaws:aws-lambda-java-events:3.11.4'
    implementation 'software.amazon.awssdk:dynamodb:2.21.0'
    implementation 'software.amazon.awssdk:dynamodb-enhanced:2.21.0'
    implementation 'com.stripe:stripe-java:24.3.0'
    implementation 'io.jsonwebtoken:jjwt-api:0.12.3'
    runtimeOnly 'io.jsonwebtoken:jjwt-impl:0.12.3'
    runtimeOnly 'io.jsonwebtoken:jjwt-jackson:0.12.3'
    implementation 'com.fasterxml.jackson.core:jackson-databind:2.16.0'
    compileOnly 'org.projectlombok:lombok:1.18.30'
    annotationProcessor 'org.projectlombok:lombok:1.18.30'
}
```

---

## Complete Java Implementation

### Project Structure

```
subscription-landing-java/
├── src/main/java/com/example/subscription/
│   ├── handler/
│   │   ├── AuthHandler.java
│   │   ├── StripeHandler.java
│   │   └── UsageHandler.java
│   ├── model/
│   │   ├── User.java
│   │   ├── AuthRequest.java
│   │   ├── AuthResponse.java
│   │   └── CheckoutRequest.java
│   ├── service/
│   │   ├── UserService.java
│   │   ├── StripeService.java
│   │   └── JwtService.java
│   ├── repository/
│   │   └── UserRepository.java
│   └── util/
│       └── ResponseUtil.java
├── src/main/resources/
│   └── application.properties
├── cdk/
│   ├── SubscriptionLandingStack.java
│   └── SubscriptionLandingApp.java
├── pom.xml
└── README.md
```

### 1. User Model (DynamoDB Entity)

```java
package com.example.subscription.model;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.*;

import java.time.Instant;

@Data
@NoArgsConstructor
@AllArgsConstructor
@DynamoDbBean
public class User {

    @Getter(onMethod_ = @DynamoDbPartitionKey)
    @Setter(onMethod_ = @DynamoDbPartitionKey)
    private String userId;

    @Getter(onMethod_ = @DynamoDbSecondaryPartitionKey(indexNames = "EmailIndex"))
    private String email;

    private String passwordHash;
    private String subscriptionStatus; // "free", "active", "cancelled"
    private Integer usageCount;
    private Integer usageLimit;
    private String stripeCustomerId;
    private String stripeSubscriptionId;
    private Instant createdAt;
    private Instant updatedAt;
}
```

### 2. JWT Service

```java
package com.example.subscription.service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration:604800000}") // 7 days in milliseconds
    private Long jwtExpiration;

    public String generateToken(String userId, String email) {
        SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));

        return Jwts.builder()
                .setSubject(userId)
                .claim("email", email)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpiration))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public Claims validateToken(String token) {
        try {
            SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));

            return Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (JwtException e) {
            throw new RuntimeException("Invalid JWT token", e);
        }
    }

    public String getUserIdFromToken(String token) {
        Claims claims = validateToken(token);
        return claims.getSubject();
    }
}
```

### 3. User Repository (DynamoDB)

```java
package com.example.subscription.repository;

import com.example.subscription.model.User;
import org.springframework.stereotype.Repository;
import software.amazon.awssdk.enhanced.dynamodb.*;
import software.amazon.awssdk.enhanced.dynamodb.model.*;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;

import java.util.Optional;

@Repository
public class UserRepository {

    private final DynamoDbEnhancedClient enhancedClient;
    private final DynamoDbTable<User> userTable;
    private final String tableName;

    public UserRepository() {
        this.tableName = System.getenv("USERS_TABLE");

        DynamoDbClient dynamoDbClient = DynamoDbClient.builder()
                .region(Region.US_EAST_1)
                .build();

        this.enhancedClient = DynamoDbEnhancedClient.builder()
                .dynamoDbClient(dynamoDbClient)
                .build();

        this.userTable = enhancedClient.table(tableName, TableSchema.fromBean(User.class));
    }

    public void save(User user) {
        userTable.putItem(user);
    }

    public Optional<User> findById(String userId) {
        User user = userTable.getItem(Key.builder().partitionValue(userId).build());
        return Optional.ofNullable(user);
    }

    public Optional<User> findByEmail(String email) {
        DynamoDbIndex<User> emailIndex = userTable.index("EmailIndex");

        QueryConditional queryConditional = QueryConditional
                .keyEqualTo(Key.builder().partitionValue(email).build());

        PageIterable<User> results = emailIndex.query(
                QueryEnhancedRequest.builder()
                        .queryConditional(queryConditional)
                        .build()
        );

        return results.items().stream().findFirst();
    }

    public void updateSubscription(String userId, String status, String customerId,
                                   String subscriptionId, Integer usageLimit) {
        User user = findById(userId).orElseThrow();
        user.setSubscriptionStatus(status);
        user.setStripeCustomerId(customerId);
        user.setStripeSubscriptionId(subscriptionId);
        user.setUsageLimit(usageLimit);
        save(user);
    }

    public void incrementUsage(String userId) {
        User user = findById(userId).orElseThrow();
        user.setUsageCount(user.getUsageCount() + 1);
        save(user);
    }
}
```

### 4. Stripe Service

```java
package com.example.subscription.service;

import com.stripe.Stripe;
import com.stripe.exception.StripeException;
import com.stripe.model.*;
import com.stripe.model.checkout.Session;
import com.stripe.param.checkout.SessionCreateParams;
import com.stripe.param.billingportal.SessionCreateParams.Builder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.util.HashMap;
import java.util.Map;

@Service
public class StripeService {

    @Value("${stripe.secret.key}")
    private String stripeSecretKey;

    @Value("${stripe.monthly.price.id}")
    private String monthlyPriceId;

    @Value("${stripe.yearly.price.id}")
    private String yearlyPriceId;

    @Value("${frontend.url}")
    private String frontendUrl;

    @PostConstruct
    public void init() {
        Stripe.apiKey = stripeSecretKey;
    }

    public Session createCheckoutSession(String priceId, String userId) throws StripeException {
        SessionCreateParams params = SessionCreateParams.builder()
                .addPaymentMethodType(SessionCreateParams.PaymentMethodType.CARD)
                .addLineItem(
                        SessionCreateParams.LineItem.builder()
                                .setPrice(priceId)
                                .setQuantity(1L)
                                .build()
                )
                .setMode(SessionCreateParams.Mode.SUBSCRIPTION)
                .setSuccessUrl(frontendUrl + "/dashboard?session_id={CHECKOUT_SESSION_ID}")
                .setCancelUrl(frontendUrl + "/pricing")
                .putMetadata("userId", userId)
                .setClientReferenceId(userId)
                .build();

        return Session.create(params);
    }

    public com.stripe.model.billingportal.Session createPortalSession(String customerId)
            throws StripeException {

        com.stripe.param.billingportal.SessionCreateParams params =
                com.stripe.param.billingportal.SessionCreateParams.builder()
                        .setCustomer(customerId)
                        .setReturnUrl(frontendUrl + "/dashboard")
                        .build();

        return com.stripe.model.billingportal.Session.create(params);
    }

    public Event constructEvent(String payload, String sigHeader, String webhookSecret)
            throws StripeException {
        return Webhook.constructEvent(payload, sigHeader, webhookSecret);
    }
}
```

### 5. Auth Handler (Lambda)

```java
package com.example.subscription.handler;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.example.subscription.model.AuthRequest;
import com.example.subscription.model.AuthResponse;
import com.example.subscription.model.User;
import com.example.subscription.repository.UserRepository;
import com.example.subscription.service.JwtService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

public class AuthHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final UserRepository userRepository = new UserRepository();
    private final JwtService jwtService = new JwtService();
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
        String path = input.getPath();

        try {
            if (path.endsWith("/register")) {
                return handleRegister(input);
            } else if (path.endsWith("/login")) {
                return handleLogin(input);
            } else if (path.endsWith("/verify")) {
                return handleVerify(input);
            }

            return createResponse(404, Map.of("error", "Not found"));
        } catch (Exception e) {
            context.getLogger().log("Error: " + e.getMessage());
            return createResponse(500, Map.of("error", "Internal server error"));
        }
    }

    private APIGatewayProxyResponseEvent handleRegister(APIGatewayProxyRequestEvent input) throws Exception {
        AuthRequest request = objectMapper.readValue(input.getBody(), AuthRequest.class);

        // Check if user already exists
        Optional<User> existingUser = userRepository.findByEmail(request.getEmail());
        if (existingUser.isPresent()) {
            return createResponse(400, Map.of("error", "Email already registered"));
        }

        // Create new user
        User user = new User();
        user.setUserId(UUID.randomUUID().toString());
        user.setEmail(request.getEmail());
        user.setPasswordHash(passwordEncoder.encode(request.getPassword()));
        user.setSubscriptionStatus("free");
        user.setUsageCount(0);
        user.setUsageLimit(5);
        user.setCreatedAt(Instant.now());

        userRepository.save(user);

        // Generate JWT token
        String token = jwtService.generateToken(user.getUserId(), user.getEmail());

        AuthResponse response = new AuthResponse(token, user);
        return createResponse(200, response);
    }

    private APIGatewayProxyResponseEvent handleLogin(APIGatewayProxyRequestEvent input) throws Exception {
        AuthRequest request = objectMapper.readValue(input.getBody(), AuthRequest.class);

        // Find user by email
        Optional<User> userOpt = userRepository.findByEmail(request.getEmail());
        if (!userOpt.isPresent()) {
            return createResponse(401, Map.of("error", "Invalid credentials"));
        }

        User user = userOpt.get();

        // Verify password
        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            return createResponse(401, Map.of("error", "Invalid credentials"));
        }

        // Generate JWT token
        String token = jwtService.generateToken(user.getUserId(), user.getEmail());

        AuthResponse response = new AuthResponse(token, user);
        return createResponse(200, response);
    }

    private APIGatewayProxyResponseEvent handleVerify(APIGatewayProxyRequestEvent input) {
        String authHeader = input.getHeaders().get("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return createResponse(401, Map.of("error", "Missing token"));
        }

        String token = authHeader.substring(7);

        try {
            String userId = jwtService.getUserIdFromToken(token);
            Optional<User> userOpt = userRepository.findById(userId);

            if (!userOpt.isPresent()) {
                return createResponse(401, Map.of("error", "User not found"));
            }

            return createResponse(200, Map.of("user", userOpt.get()));
        } catch (Exception e) {
            return createResponse(401, Map.of("error", "Invalid token"));
        }
    }

    private APIGatewayProxyResponseEvent createResponse(int statusCode, Object body) {
        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("Content-Type", "application/json");
            headers.put("Access-Control-Allow-Origin", "*");

            return new APIGatewayProxyResponseEvent()
                    .withStatusCode(statusCode)
                    .withHeaders(headers)
                    .withBody(objectMapper.writeValueAsString(body));
        } catch (Exception e) {
            return new APIGatewayProxyResponseEvent()
                    .withStatusCode(500)
                    .withBody("{\"error\":\"Internal server error\"}");
        }
    }
}
```

### 6. Stripe Handler (Lambda)

```java
package com.example.subscription.handler;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.example.subscription.model.User;
import com.example.subscription.repository.UserRepository;
import com.example.subscription.service.JwtService;
import com.example.subscription.service.StripeService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.stripe.exception.StripeException;
import com.stripe.model.Event;
import com.stripe.model.checkout.Session;
import com.stripe.model.Subscription;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class StripeHandler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final UserRepository userRepository = new UserRepository();
    private final JwtService jwtService = new JwtService();
    private final StripeService stripeService = new StripeService();
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final String webhookSecret = System.getenv("STRIPE_WEBHOOK_SECRET");

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent input, Context context) {
        String path = input.getPath();

        try {
            if (path.endsWith("/create-checkout-session")) {
                return handleCheckout(input);
            } else if (path.endsWith("/webhook")) {
                return handleWebhook(input);
            } else if (path.endsWith("/create-portal-session")) {
                return handlePortal(input);
            }

            return createResponse(404, Map.of("error", "Not found"));
        } catch (Exception e) {
            context.getLogger().log("Error: " + e.getMessage());
            return createResponse(500, Map.of("error", "Internal server error"));
        }
    }

    private APIGatewayProxyResponseEvent handleCheckout(APIGatewayProxyRequestEvent input) throws Exception {
        // Extract userId from JWT token
        String authHeader = input.getHeaders().get("Authorization");
        String token = authHeader.substring(7);
        String userId = jwtService.getUserIdFromToken(token);

        // Parse request body
        Map<String, String> body = objectMapper.readValue(input.getBody(), Map.class);
        String priceId = body.get("priceId");

        // Create checkout session
        Session session = stripeService.createCheckoutSession(priceId, userId);

        return createResponse(200, Map.of("sessionId", session.getId()));
    }

    private APIGatewayProxyResponseEvent handleWebhook(APIGatewayProxyRequestEvent input) {
        String payload = input.getBody();
        String sigHeader = input.getHeaders().get("Stripe-Signature");

        try {
            Event event = stripeService.constructEvent(payload, sigHeader, webhookSecret);

            switch (event.getType()) {
                case "checkout.session.completed":
                    handleCheckoutCompleted(event);
                    break;
                case "customer.subscription.deleted":
                    handleSubscriptionDeleted(event);
                    break;
                case "invoice.payment_failed":
                    handlePaymentFailed(event);
                    break;
                // Add other event handlers as needed
            }

            return createResponse(200, Map.of("received", true));
        } catch (Exception e) {
            return createResponse(400, Map.of("error", "Invalid signature"));
        }
    }

    private void handleCheckoutCompleted(Event event) {
        Session session = (Session) event.getDataObjectDeserializer()
                .getObject()
                .orElseThrow();

        String userId = session.getMetadata().get("userId");
        String customerId = session.getCustomer();
        String subscriptionId = session.getSubscription();

        userRepository.updateSubscription(userId, "active", customerId, subscriptionId, -1);
    }

    private void handleSubscriptionDeleted(Event event) {
        Subscription subscription = (Subscription) event.getDataObjectDeserializer()
                .getObject()
                .orElseThrow();

        String customerId = subscription.getCustomer();

        // Find user by customer ID and downgrade to free tier
        // Implementation depends on your query structure
    }

    private void handlePaymentFailed(Event event) {
        // Handle failed payment - possibly downgrade user
    }

    private APIGatewayProxyResponseEvent handlePortal(APIGatewayProxyRequestEvent input) throws Exception {
        // Extract userId from JWT token
        String authHeader = input.getHeaders().get("Authorization");
        String token = authHeader.substring(7);
        String userId = jwtService.getUserIdFromToken(token);

        // Get user's Stripe customer ID
        Optional<User> userOpt = userRepository.findById(userId);
        if (!userOpt.isPresent()) {
            return createResponse(404, Map.of("error", "User not found"));
        }

        User user = userOpt.get();
        String customerId = user.getStripeCustomerId();

        // Create portal session
        com.stripe.model.billingportal.Session portalSession =
                stripeService.createPortalSession(customerId);

        return createResponse(200, Map.of("url", portalSession.getUrl()));
    }

    private APIGatewayProxyResponseEvent createResponse(int statusCode, Object body) {
        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("Content-Type", "application/json");
            headers.put("Access-Control-Allow-Origin", "*");

            return new APIGatewayProxyResponseEvent()
                    .withStatusCode(statusCode)
                    .withHeaders(headers)
                    .withBody(objectMapper.writeValueAsString(body));
        } catch (Exception e) {
            return new APIGatewayProxyResponseEvent()
                    .withStatusCode(500)
                    .withBody("{\"error\":\"Internal server error\"}");
        }
    }
}
```

### 7. AWS CDK Stack (Java)

```java
package com.example.subscription.cdk;

import software.amazon.awscdk.*;
import software.amazon.awscdk.services.apigateway.*;
import software.amazon.awscdk.services.cloudfront.*;
import software.amazon.awscdk.services.cloudfront.origins.*;
import software.amazon.awscdk.services.dynamodb.*;
import software.amazon.awscdk.services.lambda.*;
import software.amazon.awscdk.services.lambda.Runtime;
import software.amazon.awscdk.services.s3.*;
import software.constructs.Construct;

import java.util.*;

public class SubscriptionLandingStack extends Stack {

    public SubscriptionLandingStack(final Construct scope, final String id,
                                   final StackProps props, final String environment) {
        super(scope, id, props);

        // DynamoDB Table
        Table usersTable = Table.Builder.create(this, "UsersTable")
                .tableName("subscription-users-" + environment)
                .partitionKey(Attribute.builder()
                        .name("userId")
                        .type(AttributeType.STRING)
                        .build())
                .billingMode(BillingMode.PAY_PER_REQUEST)
                .pointInTimeRecovery(true)
                .build();

        // Add Email GSI
        usersTable.addGlobalSecondaryIndex(GlobalSecondaryIndexProps.builder()
                .indexName("EmailIndex")
                .partitionKey(Attribute.builder()
                        .name("email")
                        .type(AttributeType.STRING)
                        .build())
                .projectionType(ProjectionType.ALL)
                .build());

        // Environment variables for Lambdas
        Map<String, String> lambdaEnv = new HashMap<>();
        lambdaEnv.put("ENVIRONMENT", environment);
        lambdaEnv.put("USERS_TABLE", usersTable.getTableName());
        lambdaEnv.put("STRIPE_SECRET_KEY", System.getenv("STRIPE_SECRET_KEY"));
        lambdaEnv.put("MONTHLY_PRICE_ID", System.getenv("MONTHLY_PRICE_ID"));
        lambdaEnv.put("YEARLY_PRICE_ID", System.getenv("YEARLY_PRICE_ID"));
        lambdaEnv.put("JWT_SECRET", System.getenv("JWT_SECRET"));

        // Lambda Functions
        Function registerFunction = Function.Builder.create(this, "RegisterFunction")
                .functionName("landing-register-" + environment)
                .runtime(Runtime.JAVA_17)
                .code(Code.fromAsset("target/subscription-landing-1.0.jar"))
                .handler("com.example.subscription.handler.AuthHandler::handleRequest")
                .environment(lambdaEnv)
                .timeout(Duration.seconds(30))
                .memorySize(512)
                .build();

        Function loginFunction = Function.Builder.create(this, "LoginFunction")
                .functionName("landing-login-" + environment)
                .runtime(Runtime.JAVA_17)
                .code(Code.fromAsset("target/subscription-landing-1.0.jar"))
                .handler("com.example.subscription.handler.AuthHandler::handleRequest")
                .environment(lambdaEnv)
                .timeout(Duration.seconds(30))
                .memorySize(512)
                .build();

        Function checkoutFunction = Function.Builder.create(this, "CheckoutFunction")
                .functionName("landing-checkout-" + environment)
                .runtime(Runtime.JAVA_17)
                .code(Code.fromAsset("target/subscription-landing-1.0.jar"))
                .handler("com.example.subscription.handler.StripeHandler::handleRequest")
                .environment(lambdaEnv)
                .timeout(Duration.seconds(30))
                .memorySize(512)
                .build();

        Function webhookFunction = Function.Builder.create(this, "WebhookFunction")
                .functionName("landing-webhook-" + environment)
                .runtime(Runtime.JAVA_17)
                .code(Code.fromAsset("target/subscription-landing-1.0.jar"))
                .handler("com.example.subscription.handler.StripeHandler::handleRequest")
                .environment(lambdaEnv)
                .timeout(Duration.seconds(60))
                .memorySize(512)
                .build();

        // Grant DynamoDB permissions
        usersTable.grantReadWriteData(registerFunction);
        usersTable.grantReadWriteData(loginFunction);
        usersTable.grantReadWriteData(checkoutFunction);
        usersTable.grantReadWriteData(webhookFunction);

        // API Gateway
        RestApi api = RestApi.Builder.create(this, "LandingPageAPI")
                .restApiName("subscription-landing-api-" + environment)
                .defaultCorsPreflightOptions(CorsOptions.builder()
                        .allowOrigins(Cors.ALL_ORIGINS)
                        .allowMethods(Cors.ALL_METHODS)
                        .allowHeaders(Arrays.asList("Content-Type", "Authorization", "Stripe-Signature"))
                        .build())
                .build();

        // API Routes
        Resource apiResource = api.getRoot().addResource("api");

        // Auth routes
        Resource authResource = apiResource.addResource("auth");
        authResource.addResource("register")
                .addMethod("POST", new LambdaIntegration(registerFunction));
        authResource.addResource("login")
                .addMethod("POST", new LambdaIntegration(loginFunction));

        // Stripe routes
        Resource stripeResource = apiResource.addResource("stripe");
        stripeResource.addResource("create-checkout-session")
                .addMethod("POST", new LambdaIntegration(checkoutFunction));
        stripeResource.addResource("webhook")
                .addMethod("POST", new LambdaIntegration(webhookFunction));

        // S3 Bucket for Frontend
        Bucket frontendBucket = Bucket.Builder.create(this, "FrontendBucket")
                .bucketName("subscription-landing-" + environment + "-" +
                           this.getAccount())
                .websiteIndexDocument("index.html")
                .websiteErrorDocument("index.html")
                .publicReadAccess(true)
                .blockPublicAccess(BlockPublicAccess.Builder.create()
                        .blockPublicAcls(false)
                        .blockPublicPolicy(false)
                        .ignorePublicAcls(false)
                        .restrictPublicBuckets(false)
                        .build())
                .build();

        // CloudFront Distribution
        Distribution distribution = Distribution.Builder.create(this, "CloudFrontDistribution")
                .defaultBehavior(BehaviorOptions.builder()
                        .origin(new S3Origin(frontendBucket))
                        .viewerProtocolPolicy(ViewerProtocolPolicy.REDIRECT_TO_HTTPS)
                        .build())
                .additionalBehaviors(Map.of(
                        "/api/*", BehaviorOptions.builder()
                                .origin(new HttpOrigin(
                                        api.getUrl().replace("https://", "")
                                ))
                                .viewerProtocolPolicy(ViewerProtocolPolicy.REDIRECT_TO_HTTPS)
                                .cachePolicy(CachePolicy.CACHING_DISABLED)
                                .build()
                ))
                .build();

        // Outputs
        new CfnOutput(this, "APIGatewayURL", CfnOutputProps.builder()
                .value(api.getUrl())
                .exportName(environment + "-api-url")
                .build());

        new CfnOutput(this, "CloudFrontURL", CfnOutputProps.builder()
                .value("https://" + distribution.getDistributionDomainName())
                .exportName(environment + "-frontend-url")
                .build());

        new CfnOutput(this, "FrontendBucketName", CfnOutputProps.builder()
                .value(frontendBucket.getBucketName())
                .exportName(environment + "-frontend-bucket")
                .build());
    }
}
```

### 8. CDK App Entry Point

```java
package com.example.subscription.cdk;

import software.amazon.awscdk.App;
import software.amazon.awscdk.Environment;
import software.amazon.awscdk.StackProps;

public class SubscriptionLandingApp {
    public static void main(final String[] args) {
        App app = new App();

        String environment = System.getenv("ENVIRONMENT");
        if (environment == null) {
            environment = "dev";
        }

        Environment awsEnv = Environment.builder()
                .account(System.getenv("CDK_DEFAULT_ACCOUNT"))
                .region(System.getenv("CDK_DEFAULT_REGION"))
                .build();

        new SubscriptionLandingStack(app, "subscription-landing-" + environment,
                StackProps.builder()
                        .env(awsEnv)
                        .build(),
                environment);

        app.synth();
    }
}
```

### 9. Application Properties

```properties
# application.properties
jwt.secret=${JWT_SECRET:your-secret-key-change-in-production}
jwt.expiration=604800000

stripe.secret.key=${STRIPE_SECRET_KEY}
stripe.publishable.key=${STRIPE_PUBLISHABLE_KEY}
stripe.monthly.price.id=${MONTHLY_PRICE_ID}
stripe.yearly.price.id=${YEARLY_PRICE_ID}
stripe.webhook.secret=${STRIPE_WEBHOOK_SECRET}

frontend.url=${FRONTEND_URL:http://localhost:3000}

aws.region=${AWS_REGION:us-east-1}
dynamodb.table.name=${USERS_TABLE:subscription-users-dev}
```

---

## Deployment Guide

### Prerequisites

1. **Java 17** installed
2. **Maven** or **Gradle** installed
3. **AWS CLI** configured
4. **AWS CDK CLI** installed: `npm install -g aws-cdk`
5. **Stripe Account** (test mode)

### Step 1: Build Java Application

```bash
# Using Maven
mvn clean package

# Using Gradle
gradle clean build
```

This creates a JAR file at `target/subscription-landing-1.0.jar`

### Step 2: Setup Stripe Products

Create a Java class to setup Stripe products:

```java
import com.stripe.Stripe;
import com.stripe.model.Price;
import com.stripe.model.Product;
import com.stripe.param.PriceCreateParams;
import com.stripe.param.ProductCreateParams;

public class StripeSetup {
    public static void main(String[] args) throws Exception {
        Stripe.apiKey = System.getenv("STRIPE_SECRET_KEY");

        // Create Monthly Product
        Product monthlyProduct = Product.create(
                ProductCreateParams.builder()
                        .setName("EML Converter - Monthly")
                        .setDescription("Unlimited email conversions for $10/month")
                        .putMetadata("plan_type", "monthly")
                        .build()
        );

        Price monthlyPrice = Price.create(
                PriceCreateParams.builder()
                        .setProduct(monthlyProduct.getId())
                        .setUnitAmount(1000L)
                        .setCurrency("usd")
                        .setRecurring(
                                PriceCreateParams.Recurring.builder()
                                        .setInterval(PriceCreateParams.Recurring.Interval.MONTH)
                                        .build()
                        )
                        .build()
        );

        // Create Yearly Product
        Product yearlyProduct = Product.create(
                ProductCreateParams.builder()
                        .setName("EML Converter - Yearly")
                        .setDescription("Unlimited email conversions for $80/year")
                        .putMetadata("plan_type", "yearly")
                        .build()
        );

        Price yearlyPrice = Price.create(
                PriceCreateParams.builder()
                        .setProduct(yearlyProduct.getId())
                        .setUnitAmount(8000L)
                        .setCurrency("usd")
                        .setRecurring(
                                PriceCreateParams.Recurring.builder()
                                        .setInterval(PriceCreateParams.Recurring.Interval.YEAR)
                                        .build()
                        )
                        .build()
        );

        System.out.println("Monthly Price ID: " + monthlyPrice.getId());
        System.out.println("Yearly Price ID: " + yearlyPrice.getId());
    }
}
```

Run:
```bash
export STRIPE_SECRET_KEY="sk_test_xxx"
mvn exec:java -Dexec.mainClass="com.example.subscription.StripeSetup"
```

### Step 3: Deploy with CDK

```bash
# Set environment variables
export ENVIRONMENT=dev
export STRIPE_SECRET_KEY="sk_test_xxx"
export MONTHLY_PRICE_ID="price_xxx"
export YEARLY_PRICE_ID="price_xxx"
export JWT_SECRET="your-jwt-secret"

# Bootstrap CDK (first time only)
cdk bootstrap

# Deploy
cd cdk
cdk deploy subscription-landing-dev
```

### Step 4: Configure Webhook

```java
import com.stripe.Stripe;
import com.stripe.model.WebhookEndpoint;
import com.stripe.param.WebhookEndpointCreateParams;

public class WebhookSetup {
    public static void main(String[] args) throws Exception {
        Stripe.apiKey = System.getenv("STRIPE_SECRET_KEY");

        String webhookUrl = args[0]; // Pass from command line

        WebhookEndpoint endpoint = WebhookEndpoint.create(
                WebhookEndpointCreateParams.builder()
                        .setUrl(webhookUrl)
                        .addEnabledEvent("checkout.session.completed")
                        .addEnabledEvent("customer.subscription.created")
                        .addEnabledEvent("customer.subscription.updated")
                        .addEnabledEvent("customer.subscription.deleted")
                        .addEnabledEvent("invoice.payment_succeeded")
                        .addEnabledEvent("invoice.payment_failed")
                        .setDescription("EML Converter Webhook - dev")
                        .build()
        );

        System.out.println("Webhook ID: " + endpoint.getId());
        System.out.println("Webhook Secret: " + endpoint.getSecret());
    }
}
```

Run:
```bash
export STRIPE_SECRET_KEY="sk_test_xxx"
mvn exec:java -Dexec.mainClass="com.example.subscription.WebhookSetup" \
    -Dexec.args="https://your-api-gateway.amazonaws.com/dev/api/stripe/webhook"
```

### Step 5: Update Lambda with Webhook Secret

```bash
aws lambda update-function-configuration \
    --function-name landing-webhook-dev \
    --environment "Variables={
        ENVIRONMENT=dev,
        USERS_TABLE=subscription-users-dev,
        STRIPE_SECRET_KEY=sk_test_xxx,
        STRIPE_WEBHOOK_SECRET=whsec_xxx,
        MONTHLY_PRICE_ID=price_xxx,
        YEARLY_PRICE_ID=price_xxx,
        JWT_SECRET=your-jwt-secret
    }" \
    --region us-east-1
```

### Step 6: Deploy Frontend

```bash
cd frontend
npm install

# Build with environment variables
REACT_APP_API_URL=https://your-api-gateway.amazonaws.com/dev \
REACT_APP_STRIPE_PUBLISHABLE_KEY=pk_test_xxx \
npm run build

# Deploy to S3
aws s3 sync build/ s3://subscription-landing-dev-123456789/ --delete

# Invalidate CloudFront cache
aws cloudfront create-invalidation \
    --distribution-id YOUR_DISTRIBUTION_ID \
    --paths "/*"
```

---

## Key Differences: Python vs Java

| Aspect | Python | Java |
|--------|--------|------|
| **Runtime** | Python 3.12 | Java 17 |
| **Cold Start** | ~500ms | ~2-3s (improve with SnapStart) |
| **Package Size** | Smaller (~5MB) | Larger (~20-50MB) |
| **Type Safety** | Dynamic | Static (compile-time checks) |
| **Boilerplate** | Minimal | More verbose (reduced with Lombok) |
| **AWS SDK** | boto3 | AWS SDK for Java v2 |
| **JSON Parsing** | Built-in `json` | Jackson ObjectMapper |
| **Password Hashing** | bcrypt library | Spring Security BCrypt |
| **JWT** | PyJWT | jjwt (io.jsonwebtoken) |
| **Stripe SDK** | stripe-python | stripe-java |
| **DynamoDB** | boto3 DynamoDB | DynamoDB Enhanced Client |

---

## Performance Optimization Tips for Java Lambda

1. **Use Lambda SnapStart** for faster cold starts:
```java
@CfnOutput
public static final boolean SNAP_START = true;
```

2. **Minimize JAR size**:
   - Use Maven Shade plugin
   - Exclude unnecessary dependencies
   - Use ProGuard for obfuscation/minification

3. **Reuse connections**:
```java
// Initialize outside handler
private static final DynamoDbClient dynamoClient =
    DynamoDbClient.builder().build();
```

4. **Use environment variables** instead of reading from files

5. **Implement health checks**

---

## Testing

### Unit Tests

```java
@Test
public void testRegisterUser() {
    AuthHandler handler = new AuthHandler();
    APIGatewayProxyRequestEvent request = new APIGatewayProxyRequestEvent();

    Map<String, String> body = new HashMap<>();
    body.put("email", "test@example.com");
    body.put("password", "password123");

    request.setBody(new ObjectMapper().writeValueAsString(body));
    request.setPath("/api/auth/register");

    APIGatewayProxyResponseEvent response = handler.handleRequest(request, null);

    assertEquals(200, response.getStatusCode());
}
```

### Integration Tests with Stripe

```java
@Test
public void testCheckoutSession() throws StripeException {
    Stripe.apiKey = "sk_test_xxx";

    Session session = Session.create(
            SessionCreateParams.builder()
                    .addPaymentMethodType(SessionCreateParams.PaymentMethodType.CARD)
                    .addLineItem(/* ... */)
                    .setMode(SessionCreateParams.Mode.SUBSCRIPTION)
                    .build()
    );

    assertNotNull(session.getId());
}
```

---

## Summary

This guide provides a complete roadmap for implementing a Stripe subscription system in Java, based on the Python implementation. Key points:

1. **Architecture remains the same**: Lambda + API Gateway + DynamoDB + CloudFront
2. **Java equivalents exist** for all Python libraries used
3. **CDK in Java** provides type-safe infrastructure as code
4. **Stripe API is identical** across languages
5. **Main differences**: Cold start times, verbosity, type safety

The Java implementation offers better type safety and IDE support, while Python offers faster cold starts and less boilerplate. Choose based on your team's expertise and requirements.

**Next Steps:**
1. Setup development environment
2. Create project structure
3. Implement handlers incrementally
4. Test locally with SAM
5. Deploy to AWS with CDK
6. Monitor with CloudWatch
