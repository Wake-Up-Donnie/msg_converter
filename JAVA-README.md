# Java Migration Guide - EML/MSG to PDF Converter

## Table of Contents
- [Executive Summary](#executive-summary)
- [Current Architecture Overview](#current-architecture-overview)
- [Stripe Integration Documentation](#stripe-integration-documentation)
- [AWS Infrastructure Setup](#aws-infrastructure-setup)
- [Java Migration Strategy](#java-migration-strategy)
- [Java Technology Stack Recommendations](#java-technology-stack-recommendations)
- [Detailed Migration Roadmap](#detailed-migration-roadmap)
- [Code Migration Examples](#code-migration-examples)
- [Deployment Guide for Java Version](#deployment-guide-for-java-version)
- [Testing Strategy](#testing-strategy)
- [Performance Considerations](#performance-considerations)

---

## Executive Summary

This document provides comprehensive documentation for migrating the **EML/MSG to PDF Converter** application from Python/Flask to Java. The application is currently a serverless web service deployed on AWS Lambda that converts email files (EML/MSG) and their attachments to PDF format.

**Current Tech Stack:**
- **Backend**: Python 3.12, Flask 2.3.3, Playwright, pypdf, boto3
- **Frontend**: React 18.2.0, Material-UI v5
- **Infrastructure**: AWS Lambda (containerized), API Gateway, S3, CloudFront
- **Authentication**: JWT-based or password-based
- **Payments**: Stripe 12.5.1 (partially implemented)

**Target Java Stack:**
- **Backend**: Java 17+, Spring Boot 3.x, AWS Lambda Java Runtime
- **Email Processing**: Apache James Mime4j, JavaMail API
- **PDF Generation**: Apache PDFBox, iText 7, Playwright-Java
- **Infrastructure**: Same AWS services with Java Lambda runtime

---

## Current Architecture Overview

### Application Flow

```
┌─────────────┐
│   React     │
│  Frontend   │
│ (CloudFront)│
└──────┬──────┘
       │ HTTPS
       ▼
┌─────────────┐
│ API Gateway │
│  REST API   │
└──────┬──────┘
       │
       ▼
┌─────────────────┐         ┌──────────┐
│  Lambda         │◄───────►│   S3     │
│  Container      │         │  Bucket  │
│  (Python 3.12)  │         │ (Temp)   │
└─────────────────┘         └──────────┘
       │
       ▼
┌─────────────┐
│  Stripe     │
│  Webhooks   │
└─────────────┘
```

### Key Features
1. **Email Conversion**: Converts .eml and .msg files to PDF
2. **Attachment Processing**: Extracts and converts attachments (PDF, Office docs, images)
3. **PDF Merging**: Combines email body + attachments into single PDF
4. **Cloud Storage**: Temporary S3 storage with auto-cleanup (1 day)
5. **Authentication**: Optional password or JWT-based subscription system
6. **Payment Integration**: Stripe webhook receiver (scaffolded)

### Current Backend Components

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Web Framework | Flask 2.3.3 | HTTP routing and request handling |
| Email Parsing | Python `email` lib, `extract-msg` | Parse EML/MSG files |
| PDF Generation | Playwright + Chromium | HTML to PDF rendering |
| PDF Manipulation | pypdf 4.2.0 | Merge PDFs |
| Office Conversion | pypandoc, mammoth, LibreOffice | Convert .doc/.docx to PDF |
| Cloud Storage | boto3 1.34.0 | S3 operations |
| Authentication | PyJWT 2.8.0 | JWT token generation/validation |
| Payment Processing | stripe 12.5.1 | Webhook handling |
| Image Processing | Pillow | Image conversion and embedding |

---

## Stripe Integration Documentation

### Current Implementation Status

**Files:**
- `/backend/stripe_webhook_server.py` - Standalone webhook receiver
- `/backend/models.py` - User and subscription data models

### Stripe Configuration

**Environment Variables:**
```bash
STRIPE_SECRET_KEY=sk_test_...        # Stripe API secret key
STRIPE_WEBHOOK_SECRET=whsec_...      # Webhook signing secret
```

**Stripe SDK Version:** `stripe==12.5.1`

### Webhook Server Implementation

**Location:** `backend/stripe_webhook_server.py`

**Current Functionality:**
- Standalone Flask app running on port 4242
- Receives Stripe webhook events
- Verifies webhook signatures using `stripe.Webhook.construct_event()`
- Handles `payment_intent.succeeded` event

**Code Structure:**
```python
import stripe
from flask import Flask, request

app = Flask(__name__)
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
endpoint_secret = os.getenv('STRIPE_WEBHOOK_SECRET')

@app.route('/webhook', methods=['POST'])
def webhook():
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature')

    # Verify webhook signature
    event = stripe.Webhook.construct_event(
        payload, sig_header, endpoint_secret
    )

    # Handle events
    if event['type'] == 'payment_intent.succeeded':
        payment_intent = event['data']['object']
        # TODO: Update user subscription status

    return {'status': 'success'}
```

### User Subscription Model

**Database:** SQLite (local) or could be PostgreSQL/DynamoDB for production

**User Schema (`models.py`):**
```python
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255))

    # Subscription fields
    subscription_status = db.Column(db.String(20))  # 'active', 'inactive', 'trialing'
    is_unlimited = db.Column(db.Boolean, default=False)
    free_conversions_used = db.Column(db.Integer, default=0)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
```

### Stripe Integration Roadmap

**Current Status:** 🟡 **Partial** - Webhook receiver exists but not fully integrated

**What's Implemented:**
- ✅ Stripe SDK installed
- ✅ Basic webhook receiver
- ✅ Signature verification
- ✅ User model with subscription fields

**What's Missing:**
- ❌ Checkout Session creation endpoint
- ❌ Customer Portal integration
- ❌ Subscription lifecycle webhooks (`customer.subscription.*`)
- ❌ Usage-based billing/metering
- ❌ Invoice webhooks
- ❌ Payment method management
- ❌ Stripe Customer ID linking

### Recommended Stripe Events to Handle

```python
STRIPE_EVENTS = {
    # Subscription lifecycle
    'customer.subscription.created',    # New subscription started
    'customer.subscription.updated',    # Subscription changed (upgrade/downgrade)
    'customer.subscription.deleted',    # Subscription cancelled
    'customer.subscription.trial_will_end',  # Trial ending soon

    # Payment events
    'payment_intent.succeeded',         # One-time payment successful
    'payment_intent.payment_failed',    # Payment failed
    'invoice.payment_succeeded',        # Subscription payment successful
    'invoice.payment_failed',           # Subscription payment failed

    # Customer events
    'customer.created',                 # New customer
    'customer.updated',                 # Customer details changed
    'customer.deleted',                 # Customer deleted

    # Checkout events
    'checkout.session.completed',       # Checkout flow completed
}
```

### Stripe Java SDK Equivalent

**Maven Dependency:**
```xml
<dependency>
    <groupId>com.stripe</groupId>
    <artifactId>stripe-java</artifactId>
    <version>24.16.0</version>
</dependency>
```

**Example Webhook Handler (Java/Spring Boot):**
```java
@RestController
@RequestMapping("/webhook")
public class StripeWebhookController {

    @Value("${stripe.webhook.secret}")
    private String webhookSecret;

    @PostMapping
    public ResponseEntity<String> handleWebhook(
            @RequestBody String payload,
            @RequestHeader("Stripe-Signature") String sigHeader) {

        Event event;
        try {
            event = Webhook.constructEvent(
                payload, sigHeader, webhookSecret
            );
        } catch (SignatureVerificationException e) {
            return ResponseEntity.status(400).body("Invalid signature");
        }

        switch (event.getType()) {
            case "payment_intent.succeeded":
                PaymentIntent paymentIntent = (PaymentIntent) event.getData().getObject();
                handlePaymentSuccess(paymentIntent);
                break;
            case "customer.subscription.created":
                Subscription subscription = (Subscription) event.getData().getObject();
                handleSubscriptionCreated(subscription);
                break;
        }

        return ResponseEntity.ok("Success");
    }
}
```

---

## AWS Infrastructure Setup

### Current AWS Architecture

**SAM Template:** `aws/template.yaml`

### AWS Resources

#### 1. S3 Buckets

**Temporary Files Bucket:**
```yaml
TempFilesBucket:
  Type: AWS::S3::Bucket
  Properties:
    BucketName: !Sub 'eml-converter-temp-${Environment}'
    LifecycleConfiguration:
      Rules:
        - ExpirationInDays: 1  # Auto-delete after 1 day
          Status: Enabled
    BucketEncryption:
      ServerSideEncryptionConfiguration:
        - ServerSideEncryptionByDefault:
            SSEAlgorithm: AES256
    CorsConfiguration:
      CorsRules:
        - AllowedOrigins: ['*']
          AllowedMethods: [GET, PUT, POST]
          AllowedHeaders: ['*']
```

**Frontend Static Hosting Bucket:**
```yaml
FrontendBucket:
  Type: AWS::S3::Bucket
  Properties:
    BucketName: !Sub 'eml-converter-frontend-${Environment}'
    WebsiteConfiguration:
      IndexDocument: index.html
      ErrorDocument: index.html
    PublicAccessBlockConfiguration:
      BlockPublicAcls: false
      BlockPublicPolicy: false
      IgnorePublicAcls: false
      RestrictPublicBuckets: false
```

#### 2. Lambda Function (Containerized)

**Configuration:**
```yaml
EmlConverterFunction:
  Type: AWS::Serverless::Function
  Properties:
    FunctionName: !Sub 'eml-converter-${Environment}'
    PackageType: Image  # Docker container
    ImageUri: !Ref ContainerImageUri
    MemorySize: 4096    # 4GB RAM
    Timeout: 900        # 15 minutes
    EphemeralStorage:
      Size: 2048        # 2GB /tmp storage
    Environment:
      Variables:
        S3_BUCKET: !Ref TempFilesBucket
        ENVIRONMENT: !Ref Environment
        APP_PASSWORD: !Ref AppPassword
        PLAYWRIGHT_BROWSERS_PATH: /opt/ms-playwright
    DeadLetterQueue:
      Type: SQS
      TargetArn: !GetAtt DeadLetterQueue.Arn
```

**Why Container-Based Lambda:**
- Chromium binary (~500MB) exceeds Lambda layer size limits
- Playwright dependencies require specific system libraries
- Custom fonts (Twemoji) baked into image
- Python + Playwright + Chromium = ~1.2GB total

**Docker Image Structure:**
```dockerfile
FROM public.ecr.aws/lambda/python:3.12

# Install system dependencies for Chromium
RUN yum install -y \
    liberation-fonts \
    fontconfig \
    dejavu-fonts-common \
    dejavu-sans-fonts \
    libdrm \
    libX11 \
    libxcb \
    libXcomposite \
    libXdamage \
    libXext \
    libXrandr \
    alsa-lib \
    cups-libs \
    at-spi2-atk \
    && yum clean all

# Install Python dependencies
COPY backend/requirements.txt .
RUN pip install -r requirements.txt

# Install Playwright and Chromium
RUN playwright install chromium --with-deps
RUN playwright install-deps chromium

# Set browser path
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright

# Copy application code
COPY backend/ ${LAMBDA_TASK_ROOT}/

CMD ["lambda_function.lambda_handler"]
```

#### 3. API Gateway

**Configuration:**
```yaml
EmlConverterApi:
  Type: AWS::Serverless::Api
  Properties:
    Name: !Sub 'eml-converter-api-${Environment}'
    StageName: !Ref Environment
    Cors:
      AllowOrigin: "'*'"
      AllowHeaders: "'*'"
      AllowMethods: "'GET,POST,PUT,DELETE,OPTIONS'"
    BinaryMediaTypes:
      - 'multipart/form-data'
      - 'application/pdf'
      - 'application/zip'
    GatewayResponses:
      DEFAULT_4XX:
        ResponseTemplates:
          application/json: '{"message": $context.error.messageString}'
      DEFAULT_5XX:
        ResponseTemplates:
          application/json: '{"message": "Internal server error"}'
```

**Endpoints:**
- `POST /api/convert` - Convert files
- `GET /api/download/{session_id}/{filename}` - Download PDF
- `GET /api/download-all/{session_id}` - Download ZIP
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `GET /api/health` - Health check

#### 4. CloudFront Distribution

**Purpose:**
- CDN for frontend static assets (React app)
- CDN for backend API (reduced latency)
- HTTPS termination
- Custom domain support

**Configuration:**
```yaml
CloudFrontDistribution:
  Type: AWS::CloudFront::Distribution
  Properties:
    DistributionConfig:
      Enabled: true
      HttpVersion: http2
      DefaultRootObject: index.html

      Origins:
        # Frontend S3 bucket
        - Id: S3Origin
          DomainName: !GetAtt FrontendBucket.RegionalDomainName
          S3OriginConfig:
            OriginAccessIdentity: !Sub 'origin-access-identity/cloudfront/${CloudFrontOAI}'

        # API Gateway backend
        - Id: ApiGatewayOrigin
          DomainName: !Sub '${EmlConverterApi}.execute-api.${AWS::Region}.amazonaws.com'
          CustomOriginConfig:
            OriginProtocolPolicy: https-only

      DefaultCacheBehavior:
        TargetOriginId: S3Origin
        ViewerProtocolPolicy: redirect-to-https
        CachePolicyId: 658327ea-f89d-4fab-a63d-7e88639e58f6  # CachingOptimized

      CacheBehaviors:
        # API routes (no caching)
        - PathPattern: '/api/*'
          TargetOriginId: ApiGatewayOrigin
          ViewerProtocolPolicy: redirect-to-https
          CachePolicyId: 4135ea2d-6df8-44a3-9df3-4b5a84be39ad  # CachingDisabled
          OriginRequestPolicyId: b689b0a8-53d0-40ab-baf2-68738e2966ac  # AllViewerExceptHostHeader

      ViewerCertificate:
        CloudFrontDefaultCertificate: true  # Or use ACM certificate for custom domain
```

**Current Production URL:** `https://d347djbmbuiexy.cloudfront.net`

#### 5. CloudWatch Logs

**Log Groups:**
```yaml
ApiGatewayLogGroup:
  Type: AWS::Logs::LogGroup
  Properties:
    LogGroupName: !Sub '/aws/apigateway/eml-converter-${Environment}'
    RetentionInDays: 30

LambdaLogGroup:
  Type: AWS::Logs::LogGroup
  Properties:
    LogGroupName: !Sub '/aws/lambda/eml-converter-${Environment}'
    RetentionInDays: 30
```

#### 6. Dead Letter Queue

**Purpose:** Capture failed Lambda executions for debugging

```yaml
DeadLetterQueue:
  Type: AWS::SQS::Queue
  Properties:
    QueueName: !Sub 'eml-converter-dlq-${Environment}'
    MessageRetentionPeriod: 1209600  # 14 days
```

### Deployment Process

**Script:** `aws/deploy-container.sh`

**Steps:**
```bash
#!/bin/bash

# 1. Build Docker image
docker build -t eml-converter:latest -f aws/Dockerfile .

# 2. Create ECR repository (if doesn't exist)
aws ecr create-repository --repository-name eml-converter

# 3. Tag and push to ECR
aws ecr get-login-password | docker login --username AWS --password-stdin $ECR_URI
docker tag eml-converter:latest $ECR_URI/eml-converter:latest
docker push $ECR_URI/eml-converter:latest

# 4. Deploy with SAM
sam build
sam deploy \
  --template-file aws/template.yaml \
  --stack-name eml-converter-prod \
  --parameter-overrides \
      Environment=prod \
      ContainerImageUri=$ECR_URI/eml-converter:latest \
      AppPassword=$PASSWORD \
  --capabilities CAPABILITY_IAM
```

**Usage:**
```bash
./aws/deploy-container.sh --env prod --region us-east-1 --password "secret123"
```

### AWS Costs Estimation (Monthly)

| Service | Usage | Cost |
|---------|-------|------|
| Lambda | 10,000 conversions @ 30s avg, 4GB | ~$8 |
| API Gateway | 10,000 requests | ~$0.04 |
| S3 Storage | 100GB temp (avg) | ~$2.30 |
| S3 Requests | 20,000 PUT/GET | ~$0.10 |
| CloudFront | 100GB transfer | ~$8.50 |
| CloudWatch Logs | 10GB | ~$5 |
| **Total** | | **~$24/month** |

*Assumes moderate usage; costs scale linearly with traffic*

---

## Java Migration Strategy

### Why Migrate to Java?

**Potential Benefits:**
1. **Better AWS Lambda Performance**: Java has superior cold start performance with SnapStart
2. **Enterprise Integration**: Easier integration with Java enterprise systems
3. **Type Safety**: Compile-time type checking reduces runtime errors
4. **Ecosystem**: Rich Java ecosystem for PDF, email, and document processing
5. **Scalability**: JVM optimizations for high-throughput scenarios
6. **Team Expertise**: Leverage existing Java/Spring Boot knowledge

**Challenges:**
1. **Chromium Integration**: Playwright-Java is less mature than Python version
2. **Container Size**: JVM + Chromium may increase image size
3. **Memory Usage**: JVM heap overhead on top of application memory
4. **Development Time**: Significant rewrite effort required

### Migration Approach Options

#### Option 1: Complete Rewrite (Recommended)
- **Timeline**: 6-8 weeks
- **Effort**: High
- **Risk**: Medium
- **Benefit**: Clean, maintainable Java codebase

#### Option 2: Gradual Migration
- **Timeline**: 3-4 months
- **Effort**: Medium
- **Risk**: High (dual maintenance)
- **Benefit**: Phased rollout, reduced risk

#### Option 3: Hybrid Architecture
- **Timeline**: 2-3 weeks
- **Effort**: Low
- **Risk**: Medium
- **Benefit**: Keep Python for PDF generation, Java for business logic

**Recommendation:** **Option 1 (Complete Rewrite)** for long-term maintainability

---

## Java Technology Stack Recommendations

### Core Framework
**Spring Boot 3.2+**
- Spring Web MVC for REST API
- Spring Security for authentication/authorization
- Spring Data JPA for database operations (if using RDS)
- Spring Cloud AWS for S3 integration

**Maven Dependency:**
```xml
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.2.5</version>
</parent>

<dependencies>
    <!-- Spring Boot Web -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>

    <!-- Spring Security + JWT -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-api</artifactId>
        <version>0.12.5</version>
    </dependency>

    <!-- AWS SDK v2 -->
    <dependency>
        <groupId>software.amazon.awssdk</groupId>
        <artifactId>s3</artifactId>
        <version>2.25.31</version>
    </dependency>

    <!-- Stripe -->
    <dependency>
        <groupId>com.stripe</groupId>
        <artifactId>stripe-java</artifactId>
        <version>24.16.0</version>
    </dependency>
</dependencies>
```

### Email Processing

**Apache James Mime4j** (EML parsing)
```xml
<dependency>
    <groupId>org.apache.james</groupId>
    <artifactId>apache-mime4j-core</artifactId>
    <version>0.8.10</version>
</dependency>
<dependency>
    <groupId>org.apache.james</groupId>
    <artifactId>apache-mime4j-dom</artifactId>
    <version>0.8.10</version>
</dependency>
```

**MSGParser** (MSG parsing)
```xml
<dependency>
    <groupId>com.auxilii.msgparser</groupId>
    <artifactId>msgparser</artifactId>
    <version>1.20</version>
</dependency>
```

**JavaMail API** (Alternative EML parser)
```xml
<dependency>
    <groupId>com.sun.mail</groupId>
    <artifactId>jakarta.mail</artifactId>
    <version>2.0.1</version>
</dependency>
```

### PDF Generation and Manipulation

**Apache PDFBox** (PDF creation and merging)
```xml
<dependency>
    <groupId>org.apache.pdfbox</groupId>
    <artifactId>pdfbox</artifactId>
    <version>3.0.2</version>
</dependency>
```

**iText 7** (Advanced PDF features, commercial license for production)
```xml
<dependency>
    <groupId>com.itextpdf</groupId>
    <artifactId>itext7-core</artifactId>
    <version>8.0.3</version>
    <type>pom</type>
</dependency>
```

**Flying Saucer** (HTML to PDF using CSS rendering)
```xml
<dependency>
    <groupId>org.xhtmlrenderer</groupId>
    <artifactId>flying-saucer-pdf</artifactId>
    <version>9.7.2</version>
</dependency>
```

**Playwright Java** (For Chromium-based HTML to PDF)
```xml
<dependency>
    <groupId>com.microsoft.playwright</groupId>
    <artifactId>playwright</artifactId>
    <version>1.44.0</version>
</dependency>
```

### Office Document Conversion

**Apache POI** (Word/Excel manipulation)
```xml
<dependency>
    <groupId>org.apache.poi</groupId>
    <artifactId>poi-ooxml</artifactId>
    <version>5.2.5</version>
</dependency>
```

**Documents4j** (Office to PDF using LibreOffice or MS Office)
```xml
<dependency>
    <groupId>com.documents4j</groupId>
    <artifactId>documents4j-local</artifactId>
    <version>1.1.11</version>
</dependency>
<dependency>
    <groupId>com.documents4j</groupId>
    <artifactId>documents4j-transformer-msoffice-word</artifactId>
    <version>1.1.11</version>
</dependency>
```

### AWS Lambda Runtime

**AWS Lambda Java SDK**
```xml
<dependency>
    <groupId>com.amazonaws</groupId>
    <artifactId>aws-lambda-java-core</artifactId>
    <version>1.2.3</version>
</dependency>
<dependency>
    <groupId>com.amazonaws</groupId>
    <artifactId>aws-lambda-java-events</artifactId>
    <version>3.11.5</version>
</dependency>
```

**Spring Cloud Function AWS Adapter** (Spring Boot on Lambda)
```xml
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-function-adapter-aws</artifactId>
    <version>4.1.1</version>
</dependency>
```

### Complete pom.xml Example

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>3.2.5</version>
    </parent>

    <groupId>com.example</groupId>
    <artifactId>eml-converter-java</artifactId>
    <version>1.0.0</version>
    <packaging>jar</packaging>

    <properties>
        <java.version>17</java.version>
        <maven.compiler.source>17</maven.compiler.source>
        <maven.compiler.target>17</maven.compiler.target>
        <aws-sdk.version>2.25.31</aws-sdk.version>
    </properties>

    <dependencies>
        <!-- Spring Boot -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-validation</artifactId>
        </dependency>

        <!-- AWS Lambda -->
        <dependency>
            <groupId>com.amazonaws</groupId>
            <artifactId>aws-lambda-java-core</artifactId>
            <version>1.2.3</version>
        </dependency>
        <dependency>
            <groupId>com.amazonaws</groupId>
            <artifactId>aws-lambda-java-events</artifactId>
            <version>3.11.5</version>
        </dependency>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-function-adapter-aws</artifactId>
            <version>4.1.1</version>
        </dependency>

        <!-- AWS SDK v2 -->
        <dependency>
            <groupId>software.amazon.awssdk</groupId>
            <artifactId>s3</artifactId>
            <version>${aws-sdk.version}</version>
        </dependency>
        <dependency>
            <groupId>software.amazon.awssdk</groupId>
            <artifactId>sqs</artifactId>
            <version>${aws-sdk.version}</version>
        </dependency>

        <!-- Email Processing -->
        <dependency>
            <groupId>org.apache.james</groupId>
            <artifactId>apache-mime4j-core</artifactId>
            <version>0.8.10</version>
        </dependency>
        <dependency>
            <groupId>org.apache.james</groupId>
            <artifactId>apache-mime4j-dom</artifactId>
            <version>0.8.10</version>
        </dependency>
        <dependency>
            <groupId>com.auxilii.msgparser</groupId>
            <artifactId>msgparser</artifactId>
            <version>1.20</version>
        </dependency>
        <dependency>
            <groupId>com.sun.mail</groupId>
            <artifactId>jakarta.mail</artifactId>
            <version>2.0.1</version>
        </dependency>

        <!-- PDF Generation -->
        <dependency>
            <groupId>org.apache.pdfbox</groupId>
            <artifactId>pdfbox</artifactId>
            <version>3.0.2</version>
        </dependency>
        <dependency>
            <groupId>org.xhtmlrenderer</groupId>
            <artifactId>flying-saucer-pdf</artifactId>
            <version>9.7.2</version>
        </dependency>
        <dependency>
            <groupId>com.microsoft.playwright</groupId>
            <artifactId>playwright</artifactId>
            <version>1.44.0</version>
        </dependency>

        <!-- Office Document Processing -->
        <dependency>
            <groupId>org.apache.poi</groupId>
            <artifactId>poi-ooxml</artifactId>
            <version>5.2.5</version>
        </dependency>

        <!-- Stripe -->
        <dependency>
            <groupId>com.stripe</groupId>
            <artifactId>stripe-java</artifactId>
            <version>24.16.0</version>
        </dependency>

        <!-- JWT -->
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-api</artifactId>
            <version>0.12.5</version>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-impl</artifactId>
            <version>0.12.5</version>
            <scope>runtime</scope>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-jackson</artifactId>
            <version>0.12.5</version>
            <scope>runtime</scope>
        </dependency>

        <!-- Utilities -->
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-lang3</artifactId>
        </dependency>
        <dependency>
            <groupId>commons-io</groupId>
            <artifactId>commons-io</artifactId>
            <version>2.16.1</version>
        </dependency>

        <!-- Testing -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
                <configuration>
                    <excludes>
                        <exclude>
                            <groupId>org.projectlombok</groupId>
                            <artifactId>lombok</artifactId>
                        </exclude>
                    </excludes>
                </configuration>
            </plugin>

            <!-- Shade plugin for Lambda deployment -->
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-shade-plugin</artifactId>
                <version>3.5.2</version>
                <configuration>
                    <createDependencyReducedPom>false</createDependencyReducedPom>
                    <shadedArtifactAttached>true</shadedArtifactAttached>
                    <shadedClassifierName>aws</shadedClassifierName>
                </configuration>
            </plugin>
        </plugins>
    </build>
</project>
```

---

## Detailed Migration Roadmap

### Phase 1: Project Setup and Foundation (Week 1)

**Tasks:**
1. ✅ Create new Spring Boot project structure
2. ✅ Configure Maven dependencies (pom.xml)
3. ✅ Set up development environment
4. ✅ Configure application.properties/application.yml
5. ✅ Create Dockerfile for Java Lambda
6. ✅ Set up logging (SLF4J + Logback)

**Deliverables:**
- Runnable Spring Boot application skeleton
- Configured AWS SDK clients
- Basic health check endpoint

### Phase 2: Email Parsing Implementation (Week 2)

**Tasks:**
1. ✅ Implement EML parser using Apache Mime4j
2. ✅ Implement MSG parser using MSGParser library
3. ✅ Extract email headers (From, To, Subject, Date)
4. ✅ Extract email body (HTML and plain text)
5. ✅ Extract inline images and attachments
6. ✅ Handle embedded .msg files recursively
7. ✅ Unit tests for email parsing

**Python to Java Mapping:**

| Python Module | Java Equivalent |
|---------------|-----------------|
| `email.parser.BytesParser` | `org.apache.james.mime4j.parser.MimeStreamParser` |
| `extract_msg.Message` | `com.auxilii.msgparser.MsgParser` |
| `email.message.EmailMessage` | `org.apache.james.mime4j.dom.Message` |

**Code Example:**
```java
@Service
public class EmailParserService {

    public ParsedEmail parseEml(byte[] emlBytes) throws IOException {
        MimeConfig config = MimeConfig.DEFAULT;
        MessageBuilder builder = new DefaultMessageBuilder();

        Message message = builder.parseMessage(
            new ByteArrayInputStream(emlBytes)
        );

        return ParsedEmail.builder()
            .subject(message.getSubject())
            .from(extractAddresses(message.getFrom()))
            .to(extractAddresses(message.getTo()))
            .date(message.getDate())
            .body(extractBody(message))
            .attachments(extractAttachments(message))
            .build();
    }

    public ParsedEmail parseMsg(byte[] msgBytes) throws IOException {
        MsgParser parser = new MsgParser();
        Message msg = parser.parseMsg(new ByteArrayInputStream(msgBytes));

        return ParsedEmail.builder()
            .subject(msg.getSubject())
            .from(msg.getFromEmail())
            .to(msg.getToEmail())
            .date(msg.getDate())
            .body(msg.getBodyHTML())
            .attachments(convertAttachments(msg.getAttachments()))
            .build();
    }
}
```

### Phase 3: PDF Generation (Week 3-4)

**Tasks:**
1. ✅ Implement HTML to PDF conversion using Playwright-Java
2. ✅ Alternative HTML to PDF using Flying Saucer (fallback)
3. ✅ Format email headers for PDF rendering
4. ✅ Style email body HTML
5. ✅ Embed Twemoji font for emoji support
6. ✅ Handle image embedding (base64 and inline)
7. ✅ Merge multiple PDFs using Apache PDFBox
8. ✅ Unit and integration tests

**Playwright-Java Example:**
```java
@Service
public class PdfGenerationService {

    private final Playwright playwright;
    private final Browser browser;

    @PostConstruct
    public void init() {
        playwright = Playwright.create();
        browser = playwright.chromium().launch(new BrowserType.LaunchOptions()
            .setHeadless(true));
    }

    public byte[] htmlToPdf(String html) {
        Page page = browser.newPage();
        page.setContent(html);

        byte[] pdf = page.pdf(new Page.PdfOptions()
            .setFormat("A4")
            .setPrintBackground(true)
            .setMargin(new Page.PdfOptions.Margin()
                .setTop("1cm")
                .setRight("1cm")
                .setBottom("1cm")
                .setLeft("1cm")));

        page.close();
        return pdf;
    }

    public byte[] mergePdfs(List<byte[]> pdfList) throws IOException {
        PDFMergerUtility merger = new PDFMergerUtility();
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        for (byte[] pdfBytes : pdfList) {
            merger.addSource(new ByteArrayInputStream(pdfBytes));
        }

        merger.setDestinationStream(output);
        merger.mergeDocuments(MemoryUsageSetting.setupMainMemoryOnly());

        return output.toByteArray();
    }

    @PreDestroy
    public void cleanup() {
        if (browser != null) browser.close();
        if (playwright != null) playwright.close();
    }
}
```

### Phase 4: Attachment Processing (Week 4)

**Tasks:**
1. ✅ Convert image attachments to PDF
2. ✅ Convert Word/DOCX to PDF using Apache POI
3. ✅ Handle PDF attachments (pass-through)
4. ✅ Handle text file attachments
5. ✅ Recursive processing of embedded .msg files

**Office to PDF Example:**
```java
@Service
public class DocumentConverterService {

    public byte[] wordToPdf(byte[] docxBytes) throws IOException {
        try (ByteArrayInputStream input = new ByteArrayInputStream(docxBytes);
             XWPFDocument document = new XWPFDocument(input);
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {

            PdfOptions options = PdfOptions.create();
            PdfConverter.getInstance().convert(document, output, options);
            return output.toByteArray();
        }
    }

    public byte[] imageToPdf(byte[] imageBytes) throws IOException {
        PDDocument document = new PDDocument();
        PDPage page = new PDPage();
        document.addPage(page);

        PDImageXObject image = PDImageXObject.createFromByteArray(
            document, imageBytes, "image"
        );

        try (PDPageContentStream contentStream =
                new PDPageContentStream(document, page)) {
            contentStream.drawImage(image, 50, 50);
        }

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        document.save(output);
        document.close();

        return output.toByteArray();
    }
}
```

### Phase 5: AWS S3 Integration (Week 5)

**Tasks:**
1. ✅ Implement S3 upload/download using AWS SDK v2
2. ✅ Generate pre-signed URLs for file access
3. ✅ Implement temporary file cleanup (lifecycle policies)
4. ✅ Error handling and retry logic

**S3 Service Example:**
```java
@Service
public class S3Service {

    private final S3Client s3Client;
    private final S3Presigner s3Presigner;

    @Value("${aws.s3.bucket}")
    private String bucketName;

    public S3Service() {
        this.s3Client = S3Client.builder()
            .region(Region.US_EAST_1)
            .build();
        this.s3Presigner = S3Presigner.create();
    }

    public String uploadFile(String key, byte[] content, String contentType) {
        PutObjectRequest request = PutObjectRequest.builder()
            .bucket(bucketName)
            .key(key)
            .contentType(contentType)
            .build();

        s3Client.putObject(request,
            RequestBody.fromBytes(content));

        return key;
    }

    public byte[] downloadFile(String key) {
        GetObjectRequest request = GetObjectRequest.builder()
            .bucket(bucketName)
            .key(key)
            .build();

        ResponseBytes<GetObjectResponse> response =
            s3Client.getObjectAsBytes(request);

        return response.asByteArray();
    }

    public String generatePresignedUrl(String key, Duration expiration) {
        GetObjectRequest request = GetObjectRequest.builder()
            .bucket(bucketName)
            .key(key)
            .build();

        GetObjectPresignRequest presignRequest =
            GetObjectPresignRequest.builder()
                .signatureDuration(expiration)
                .getObjectRequest(request)
                .build();

        PresignedGetObjectRequest presigned =
            s3Presigner.presignGetObject(presignRequest);

        return presigned.url().toString();
    }
}
```

### Phase 6: REST API Implementation (Week 6)

**Tasks:**
1. ✅ Implement `/convert` endpoint
2. ✅ Implement `/download/{sessionId}/{filename}` endpoint
3. ✅ Implement `/download-all/{sessionId}` endpoint (ZIP generation)
4. ✅ Implement `/health` endpoint
5. ✅ Request validation and error handling
6. ✅ CORS configuration
7. ✅ Multipart file upload handling

**Controller Example:**
```java
@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class ConversionController {

    private final ConversionService conversionService;
    private final S3Service s3Service;

    @PostMapping("/convert")
    public ResponseEntity<ConversionResponse> convert(
            @RequestParam("files") MultipartFile[] files,
            @RequestHeader(value = "X-App-Password", required = false) String password) {

        // Validate password if enabled
        if (authService.isPasswordRequired() &&
            !authService.validatePassword(password)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ConversionResponse("Invalid password"));
        }

        // Process files
        String sessionId = UUID.randomUUID().toString();
        List<ConversionResult> results = new ArrayList<>();

        for (MultipartFile file : files) {
            try {
                byte[] pdf = conversionService.convertToPdf(
                    file.getBytes(),
                    file.getOriginalFilename()
                );

                String s3Key = String.format("%s/%s.pdf",
                    sessionId,
                    FilenameUtils.getBaseName(file.getOriginalFilename())
                );

                s3Service.uploadFile(s3Key, pdf, "application/pdf");

                results.add(new ConversionResult(
                    file.getOriginalFilename(),
                    s3Key,
                    "success"
                ));
            } catch (Exception e) {
                results.add(new ConversionResult(
                    file.getOriginalFilename(),
                    null,
                    "error: " + e.getMessage()
                ));
            }
        }

        return ResponseEntity.ok(new ConversionResponse(sessionId, results));
    }

    @GetMapping("/download/{sessionId}/{filename}")
    public ResponseEntity<byte[]> download(
            @PathVariable String sessionId,
            @PathVariable String filename) {

        String key = String.format("%s/%s", sessionId, filename);
        byte[] pdf = s3Service.downloadFile(key);

        return ResponseEntity.ok()
            .contentType(MediaType.APPLICATION_PDF)
            .header(HttpHeaders.CONTENT_DISPOSITION,
                "attachment; filename=\"" + filename + "\"")
            .body(pdf);
    }

    @GetMapping("/download-all/{sessionId}")
    public ResponseEntity<byte[]> downloadAll(@PathVariable String sessionId)
            throws IOException {

        List<byte[]> pdfs = s3Service.listAndDownloadAll(sessionId);
        byte[] zip = zipService.createZip(pdfs);

        return ResponseEntity.ok()
            .contentType(MediaType.parseMediaType("application/zip"))
            .header(HttpHeaders.CONTENT_DISPOSITION,
                "attachment; filename=\"converted_files.zip\"")
            .body(zip);
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        return ResponseEntity.ok(Map.of(
            "status", "healthy",
            "version", "1.0.0"
        ));
    }
}
```

### Phase 7: Authentication and JWT (Week 7)

**Tasks:**
1. ✅ Implement user registration
2. ✅ Implement user login with JWT generation
3. ✅ Implement JWT validation filter
4. ✅ Password hashing (BCrypt)
5. ✅ Secure endpoints with Spring Security
6. ✅ Database integration (RDS PostgreSQL or DynamoDB)

**Security Configuration:**
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**", "/api/health").permitAll()
                .requestMatchers("/api/convert").authenticated()
                .requestMatchers("/api/download/**").authenticated()
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .addFilterBefore(jwtAuthenticationFilter(),
                UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter(jwtService, userDetailsService);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

**JWT Service:**
```java
@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private long expiration;

    public String generateToken(String email) {
        return Jwts.builder()
            .setSubject(email)
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + expiration))
            .signWith(Keys.hmacShaKeyFor(secret.getBytes()), SignatureAlgorithm.HS256)
            .compact();
    }

    public Claims validateToken(String token) {
        return Jwts.parserBuilder()
            .setSigningKey(Keys.hmacShaKeyFor(secret.getBytes()))
            .build()
            .parseClaimsJws(token)
            .getBody();
    }
}
```

### Phase 8: Stripe Integration (Week 7)

**Tasks:**
1. ✅ Implement Stripe webhook endpoint
2. ✅ Verify webhook signatures
3. ✅ Handle subscription events
4. ✅ Create Checkout Session endpoint
5. ✅ Link Stripe Customer IDs to users
6. ✅ Implement usage tracking

**Stripe Controller:**
```java
@RestController
@RequestMapping("/api/stripe")
public class StripeWebhookController {

    @Value("${stripe.webhook.secret}")
    private String webhookSecret;

    private final SubscriptionService subscriptionService;

    @PostMapping("/webhook")
    public ResponseEntity<String> handleWebhook(
            @RequestBody String payload,
            @RequestHeader("Stripe-Signature") String signature) {

        Event event;
        try {
            event = Webhook.constructEvent(payload, signature, webhookSecret);
        } catch (SignatureVerificationException e) {
            log.error("Invalid signature", e);
            return ResponseEntity.status(400).body("Invalid signature");
        }

        switch (event.getType()) {
            case "customer.subscription.created":
                handleSubscriptionCreated(event);
                break;
            case "customer.subscription.updated":
                handleSubscriptionUpdated(event);
                break;
            case "customer.subscription.deleted":
                handleSubscriptionDeleted(event);
                break;
            case "invoice.payment_succeeded":
                handlePaymentSucceeded(event);
                break;
            case "invoice.payment_failed":
                handlePaymentFailed(event);
                break;
        }

        return ResponseEntity.ok("Success");
    }

    @PostMapping("/create-checkout-session")
    public ResponseEntity<Map<String, String>> createCheckoutSession(
            @RequestBody CheckoutRequest request,
            @AuthenticationPrincipal User user) throws StripeException {

        SessionCreateParams params = SessionCreateParams.builder()
            .setMode(SessionCreateParams.Mode.SUBSCRIPTION)
            .setCustomerEmail(user.getEmail())
            .addLineItem(
                SessionCreateParams.LineItem.builder()
                    .setPrice(request.getPriceId())
                    .setQuantity(1L)
                    .build()
            )
            .setSuccessUrl(request.getSuccessUrl())
            .setCancelUrl(request.getCancelUrl())
            .build();

        Session session = Session.create(params);

        return ResponseEntity.ok(Map.of(
            "sessionId", session.getId(),
            "url", session.getUrl()
        ));
    }

    private void handleSubscriptionCreated(Event event) {
        Subscription subscription = (Subscription) event.getDataObjectDeserializer()
            .getObject()
            .orElseThrow();

        subscriptionService.activateSubscription(
            subscription.getCustomer(),
            subscription.getId(),
            subscription.getStatus()
        );
    }
}
```

### Phase 9: Lambda Integration (Week 8)

**Tasks:**
1. ✅ Create Lambda handler entry point
2. ✅ Configure Spring Cloud Function for Lambda
3. ✅ Build and package application
4. ✅ Create Dockerfile for Java Lambda
5. ✅ Deploy to AWS Lambda
6. ✅ Integration testing

**Lambda Handler:**
```java
public class StreamLambdaHandler implements RequestStreamHandler {

    private static final SpringBootLambdaContainerHandler<AwsProxyRequest, AwsProxyResponse> handler;

    static {
        try {
            handler = SpringBootLambdaContainerHandler.getAwsProxyHandler(
                Application.class
            );
        } catch (ContainerInitializationException e) {
            throw new RuntimeException("Could not initialize Spring Boot application", e);
        }
    }

    @Override
    public void handleRequest(InputStream input, OutputStream output, Context context)
            throws IOException {
        handler.proxyStream(input, output, context);
    }
}
```

**Dockerfile for Java Lambda:**
```dockerfile
FROM public.ecr.aws/lambda/java:17

# Install Chromium dependencies
RUN yum install -y \
    liberation-fonts \
    fontconfig \
    dejavu-sans-fonts \
    libdrm \
    libX11 \
    cups-libs \
    && yum clean all

# Copy Maven build output
COPY target/eml-converter-java-1.0.0-aws.jar ${LAMBDA_TASK_ROOT}/lib/

# Install Playwright and Chromium
RUN java -jar ${LAMBDA_TASK_ROOT}/lib/eml-converter-java-1.0.0-aws.jar \
    com.microsoft.playwright.CLI install chromium --with-deps

# Set handler
CMD ["com.example.emlconverter.StreamLambdaHandler::handleRequest"]
```

### Phase 10: Testing and Documentation (Week 8)

**Tasks:**
1. ✅ Unit tests for all services (target 80% coverage)
2. ✅ Integration tests for API endpoints
3. ✅ End-to-end testing with real files
4. ✅ Performance testing and optimization
5. ✅ Update documentation (README, API docs)
6. ✅ Create migration guide

---

## Code Migration Examples

### Example 1: Email Header Extraction

**Python (Original):**
```python
def extract_email_metadata(msg):
    headers = {
        'from': msg.get('From', ''),
        'to': msg.get('To', ''),
        'cc': msg.get('Cc', ''),
        'subject': msg.get('Subject', ''),
        'date': msg.get('Date', '')
    }
    return headers
```

**Java (Migrated):**
```java
@Service
public class EmailMetadataExtractor {

    public EmailHeaders extractHeaders(Message message) {
        return EmailHeaders.builder()
            .from(extractAddressField(message.getFrom()))
            .to(extractAddressField(message.getTo()))
            .cc(extractAddressField(message.getCc()))
            .subject(message.getSubject())
            .date(message.getDate())
            .build();
    }

    private String extractAddressField(AddressList addresses) {
        if (addresses == null || addresses.isEmpty()) {
            return "";
        }
        return addresses.stream()
            .map(address -> {
                if (address instanceof Mailbox) {
                    Mailbox mailbox = (Mailbox) address;
                    String name = mailbox.getName();
                    String email = mailbox.getAddress();
                    return name != null ?
                        String.format("%s <%s>", name, email) : email;
                }
                return address.toString();
            })
            .collect(Collectors.joining(", "));
    }
}
```

### Example 2: HTML Body Extraction

**Python (Original):**
```python
def get_email_body(msg):
    body_html = ""
    body_text = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == 'text/html':
                body_html = part.get_payload(decode=True).decode('utf-8', errors='ignore')
            elif content_type == 'text/plain':
                body_text = part.get_payload(decode=True).decode('utf-8', errors='ignore')
    else:
        body_text = msg.get_payload(decode=True).decode('utf-8', errors='ignore')

    return body_html or body_text
```

**Java (Migrated):**
```java
@Service
public class EmailBodyExtractor {

    public EmailBody extractBody(Message message) throws IOException {
        EmailBody.EmailBodyBuilder builder = EmailBody.builder();

        Body body = message.getBody();

        if (body instanceof Multipart) {
            Multipart multipart = (Multipart) body;
            extractFromMultipart(multipart, builder);
        } else if (body instanceof TextBody) {
            TextBody textBody = (TextBody) body;
            String content = IOUtils.toString(textBody.getInputStream(),
                StandardCharsets.UTF_8);

            if (message.getMimeType().equals("text/html")) {
                builder.html(content);
            } else {
                builder.text(content);
            }
        }

        return builder.build();
    }

    private void extractFromMultipart(Multipart multipart,
                                      EmailBody.EmailBodyBuilder builder)
            throws IOException {
        for (Entity part : multipart.getBodyParts()) {
            String mimeType = part.getMimeType();
            Body body = part.getBody();

            if (body instanceof TextBody) {
                String content = IOUtils.toString(
                    ((TextBody) body).getInputStream(),
                    StandardCharsets.UTF_8
                );

                if ("text/html".equals(mimeType)) {
                    builder.html(content);
                } else if ("text/plain".equals(mimeType)) {
                    builder.text(content);
                }
            } else if (body instanceof Multipart) {
                extractFromMultipart((Multipart) body, builder);
            }
        }
    }
}
```

### Example 3: PDF Merging

**Python (Original):**
```python
from pypdf import PdfMerger

def merge_pdfs(pdf_list):
    merger = PdfMerger()
    for pdf_bytes in pdf_list:
        merger.append(io.BytesIO(pdf_bytes))

    output = io.BytesIO()
    merger.write(output)
    merger.close()

    return output.getvalue()
```

**Java (Migrated):**
```java
@Service
public class PdfMergerService {

    public byte[] mergePdfs(List<byte[]> pdfList) throws IOException {
        PDFMergerUtility merger = new PDFMergerUtility();
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        for (byte[] pdfBytes : pdfList) {
            merger.addSource(new ByteArrayInputStream(pdfBytes));
        }

        merger.setDestinationStream(output);
        merger.mergeDocuments(MemoryUsageSetting.setupMainMemoryOnly());

        return output.toByteArray();
    }
}
```

### Example 4: S3 File Upload

**Python (Original):**
```python
import boto3

s3_client = boto3.client('s3')

def upload_to_s3(bucket, key, data, content_type):
    s3_client.put_object(
        Bucket=bucket,
        Key=key,
        Body=data,
        ContentType=content_type
    )
```

**Java (Migrated):**
```java
@Service
public class S3StorageService {

    private final S3Client s3Client;

    @Value("${aws.s3.bucket}")
    private String bucketName;

    public S3StorageService() {
        this.s3Client = S3Client.builder()
            .region(Region.US_EAST_1)
            .build();
    }

    public void uploadToS3(String key, byte[] data, String contentType) {
        PutObjectRequest request = PutObjectRequest.builder()
            .bucket(bucketName)
            .key(key)
            .contentType(contentType)
            .build();

        s3Client.putObject(request, RequestBody.fromBytes(data));

        log.info("Uploaded file to S3: s3://{}/{}", bucketName, key);
    }
}
```

### Example 5: Stripe Webhook Verification

**Python (Original):**
```python
import stripe

@app.route('/webhook', methods=['POST'])
def webhook():
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature')

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, webhook_secret
        )
    except ValueError:
        return 'Invalid payload', 400
    except stripe.error.SignatureVerificationError:
        return 'Invalid signature', 400

    if event['type'] == 'payment_intent.succeeded':
        payment_intent = event['data']['object']
        handle_payment_success(payment_intent)

    return jsonify({'status': 'success'})
```

**Java (Migrated):**
```java
@RestController
@RequestMapping("/webhook")
public class StripeWebhookController {

    @Value("${stripe.webhook.secret}")
    private String webhookSecret;

    private final PaymentService paymentService;

    @PostMapping
    public ResponseEntity<Map<String, String>> handleWebhook(
            @RequestBody String payload,
            @RequestHeader("Stripe-Signature") String signature) {

        Event event;
        try {
            event = Webhook.constructEvent(payload, signature, webhookSecret);
        } catch (JsonSyntaxException e) {
            log.error("Invalid payload", e);
            return ResponseEntity.badRequest()
                .body(Map.of("error", "Invalid payload"));
        } catch (SignatureVerificationException e) {
            log.error("Invalid signature", e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Invalid signature"));
        }

        EventDataObjectDeserializer deserializer = event.getDataObjectDeserializer();

        switch (event.getType()) {
            case "payment_intent.succeeded":
                PaymentIntent paymentIntent = (PaymentIntent) deserializer
                    .getObject()
                    .orElseThrow(() -> new IllegalStateException("Missing object"));
                paymentService.handlePaymentSuccess(paymentIntent);
                break;
        }

        return ResponseEntity.ok(Map.of("status", "success"));
    }
}
```

---

## Deployment Guide for Java Version

### 1. Build the Application

**Maven Build:**
```bash
mvn clean package -DskipTests
```

**Output:** `target/eml-converter-java-1.0.0-aws.jar` (shaded JAR with all dependencies)

### 2. Build Docker Image

**Dockerfile:**
```dockerfile
FROM public.ecr.aws/lambda/java:17

# Install system dependencies for Chromium
RUN yum install -y \
    liberation-fonts \
    fontconfig \
    dejavu-sans-fonts \
    libdrm \
    libX11 \
    libxcb \
    libXcomposite \
    libXdamage \
    libXext \
    libXrandr \
    cups-libs \
    at-spi2-atk \
    alsa-lib \
    && yum clean all

# Copy application JAR
COPY target/eml-converter-java-1.0.0-aws.jar ${LAMBDA_TASK_ROOT}/lib/

# Install Playwright Chromium
WORKDIR /tmp
RUN java -cp ${LAMBDA_TASK_ROOT}/lib/eml-converter-java-1.0.0-aws.jar \
    com.microsoft.playwright.CLI install chromium
RUN java -cp ${LAMBDA_TASK_ROOT}/lib/eml-converter-java-1.0.0-aws.jar \
    com.microsoft.playwright.CLI install-deps chromium

# Set Playwright browser path
ENV PLAYWRIGHT_BROWSERS_PATH=/root/.cache/ms-playwright

# Set Lambda handler
CMD ["com.example.emlconverter.StreamLambdaHandler::handleRequest"]
```

**Build Command:**
```bash
docker build -t eml-converter-java:latest -f Dockerfile .
```

### 3. Push to ECR

```bash
# Authenticate with ECR
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin \
  123456789012.dkr.ecr.us-east-1.amazonaws.com

# Create repository (if doesn't exist)
aws ecr create-repository --repository-name eml-converter-java --region us-east-1

# Tag and push
docker tag eml-converter-java:latest \
  123456789012.dkr.ecr.us-east-1.amazonaws.com/eml-converter-java:latest

docker push 123456789012.dkr.ecr.us-east-1.amazonaws.com/eml-converter-java:latest
```

### 4. Update SAM Template

**template.yaml (Java version):**
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31

Parameters:
  Environment:
    Type: String
    Default: dev
  ContainerImageUri:
    Type: String
    Description: ECR image URI
  JwtSecret:
    Type: String
    NoEcho: true
  StripeSecretKey:
    Type: String
    NoEcho: true
  StripeWebhookSecret:
    Type: String
    NoEcho: true

Resources:
  EmlConverterFunction:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: !Sub 'eml-converter-java-${Environment}'
      PackageType: Image
      ImageUri: !Ref ContainerImageUri
      MemorySize: 4096
      Timeout: 900
      EphemeralStorage:
        Size: 2048
      Environment:
        Variables:
          SPRING_PROFILES_ACTIVE: lambda
          AWS_S3_BUCKET: !Ref TempFilesBucket
          AWS_REGION: !Ref AWS::Region
          JWT_SECRET: !Ref JwtSecret
          STRIPE_SECRET_KEY: !Ref StripeSecretKey
          STRIPE_WEBHOOK_SECRET: !Ref StripeWebhookSecret
          PLAYWRIGHT_BROWSERS_PATH: /root/.cache/ms-playwright
          JAVA_TOOL_OPTIONS: >-
            -XX:+TieredCompilation
            -XX:TieredStopAtLevel=1
            -Dspring.main.lazy-initialization=true
      Events:
        ApiEvent:
          Type: Api
          Properties:
            RestApiId: !Ref EmlConverterApi
            Path: /{proxy+}
            Method: ANY
      Policies:
        - S3FullAccessPolicy:
            BucketName: !Ref TempFilesBucket
      DeadLetterQueue:
        Type: SQS
        TargetArn: !GetAtt DeadLetterQueue.Arn
    Metadata:
      DockerTag: v1
      DockerContext: .
      Dockerfile: Dockerfile

  # ... (rest of resources same as Python version)
```

### 5. Deploy with SAM

```bash
sam deploy \
  --template-file template.yaml \
  --stack-name eml-converter-java-prod \
  --parameter-overrides \
      Environment=prod \
      ContainerImageUri=123456789012.dkr.ecr.us-east-1.amazonaws.com/eml-converter-java:latest \
      JwtSecret=your-secret-key \
      StripeSecretKey=sk_live_... \
      StripeWebhookSecret=whsec_... \
  --capabilities CAPABILITY_IAM \
  --region us-east-1
```

### 6. Enable Lambda SnapStart (Optional)

**For faster cold starts:**
```bash
aws lambda update-function-configuration \
  --function-name eml-converter-java-prod \
  --snap-start ApplyOn=PublishedVersions \
  --region us-east-1

aws lambda publish-version \
  --function-name eml-converter-java-prod \
  --region us-east-1
```

### 7. Configure API Gateway Custom Domain (Optional)

**Route 53 + ACM Certificate:**
```yaml
CustomDomain:
  Type: AWS::ApiGateway::DomainName
  Properties:
    DomainName: api.example.com
    CertificateArn: !Ref Certificate
    EndpointConfiguration:
      Types:
        - EDGE

BasePathMapping:
  Type: AWS::ApiGateway::BasePathMapping
  Properties:
    DomainName: !Ref CustomDomain
    RestApiId: !Ref EmlConverterApi
    Stage: !Ref Environment
```

---

## Testing Strategy

### Unit Testing

**Test Structure:**
```
src/test/java/
├── com/example/emlconverter/
│   ├── service/
│   │   ├── EmailParserServiceTest.java
│   │   ├── PdfGenerationServiceTest.java
│   │   ├── ConversionServiceTest.java
│   │   └── S3ServiceTest.java
│   ├── controller/
│   │   ├── ConversionControllerTest.java
│   │   └── StripeWebhookControllerTest.java
│   └── util/
│       └── EmailUtilsTest.java
```

**Example Unit Test:**
```java
@SpringBootTest
class EmailParserServiceTest {

    @Autowired
    private EmailParserService emailParserService;

    @Test
    void testParseEmlFile() throws IOException {
        // Given
        byte[] emlBytes = loadTestFile("sample.eml");

        // When
        ParsedEmail result = emailParserService.parseEml(emlBytes);

        // Then
        assertThat(result.getSubject()).isEqualTo("Test Email");
        assertThat(result.getFrom()).contains("sender@example.com");
        assertThat(result.getBody()).isNotEmpty();
        assertThat(result.getAttachments()).hasSize(2);
    }

    @Test
    void testParseMsgFile() throws IOException {
        byte[] msgBytes = loadTestFile("sample.msg");
        ParsedEmail result = emailParserService.parseMsg(msgBytes);

        assertThat(result).isNotNull();
        assertThat(result.getSubject()).isNotBlank();
    }

    private byte[] loadTestFile(String filename) throws IOException {
        return Files.readAllBytes(
            Paths.get("src/test/resources/test-files/" + filename)
        );
    }
}
```

### Integration Testing

**API Endpoint Test:**
```java
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class ConversionControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private S3Service s3Service;

    @Test
    void testConvertEndpoint() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
            "files",
            "test.eml",
            "message/rfc822",
            loadTestFile("sample.eml")
        );

        mockMvc.perform(multipart("/api/convert")
                .file(file)
                .header("X-App-Password", "test123"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.sessionId").exists())
            .andExpect(jsonPath("$.results[0].status").value("success"));
    }

    @Test
    void testConvertUnauthorized() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
            "files",
            "test.eml",
            "message/rfc822",
            new byte[0]
        );

        mockMvc.perform(multipart("/api/convert").file(file))
            .andExpect(status().isUnauthorized());
    }
}
```

### End-to-End Testing

**Cucumber BDD Tests:**
```gherkin
# src/test/resources/features/email-conversion.feature

Feature: Email to PDF Conversion

  Scenario: Convert single EML file to PDF
    Given I have an EML file "sample.eml"
    When I upload the file to /api/convert
    Then the conversion should succeed
    And I should receive a PDF download link
    And the PDF should contain the email content

  Scenario: Convert MSG file with attachments
    Given I have a MSG file "with-attachments.msg"
    When I upload the file to /api/convert
    Then the conversion should succeed
    And the PDF should include all attachments

  Scenario: Batch conversion of multiple files
    Given I have 5 EML files
    When I upload all files to /api/convert
    Then all conversions should succeed
    And I should be able to download a ZIP file with all PDFs
```

**Test Implementation:**
```java
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class ConversionStepDefinitions {

    @LocalServerPort
    private int port;

    private RestTemplate restTemplate = new RestTemplate();
    private ResponseEntity<ConversionResponse> response;

    @Given("I have an EML file {string}")
    public void iHaveAnEMLFile(String filename) {
        // Load test file
    }

    @When("I upload the file to /api/convert")
    public void iUploadTheFile() {
        String url = "http://localhost:" + port + "/api/convert";
        // Perform multipart upload
    }

    @Then("the conversion should succeed")
    public void theConversionShouldSucceed() {
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().getResults().get(0).getStatus())
            .isEqualTo("success");
    }
}
```

### Performance Testing

**JMeter Test Plan:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<jmeterTestPlan version="1.2">
  <hashTree>
    <TestPlan>
      <stringProp name="TestPlan.comments">EML Converter Load Test</stringProp>
      <boolProp name="TestPlan.functional_mode">false</boolProp>
      <elementProp name="TestPlan.user_defined_variables" elementType="Arguments">
        <collectionProp name="Arguments.arguments"/>
      </elementProp>
    </TestPlan>
    <hashTree>
      <ThreadGroup>
        <stringProp name="ThreadGroup.num_threads">100</stringProp>
        <stringProp name="ThreadGroup.ramp_time">60</stringProp>
        <stringProp name="ThreadGroup.duration">300</stringProp>
      </ThreadGroup>
      <hashTree>
        <HTTPSamplerProxy>
          <stringProp name="HTTPSampler.domain">api.example.com</stringProp>
          <stringProp name="HTTPSampler.path">/api/convert</stringProp>
          <stringProp name="HTTPSampler.method">POST</stringProp>
          <elementProp name="HTTPsampler.Files" elementType="HTTPFileArgs">
            <collectionProp name="HTTPFileArgs.files">
              <elementProp name="test.eml" elementType="HTTPFileArg">
                <stringProp name="File.path">test-files/sample.eml</stringProp>
                <stringProp name="File.paramname">files</stringProp>
                <stringProp name="File.mimetype">message/rfc822</stringProp>
              </elementProp>
            </collectionProp>
          </elementProp>
        </HTTPSamplerProxy>
      </hashTree>
    </hashTree>
  </hashTree>
</jmeterTestPlan>
```

---

## Performance Considerations

### Java vs Python Performance Comparison

| Metric | Python (Current) | Java (Estimated) |
|--------|------------------|------------------|
| Cold Start | 5-8 seconds | 3-5 seconds (with SnapStart: <1s) |
| Warm Execution | 15-30 seconds | 10-20 seconds |
| Memory Usage | 2-3 GB | 2.5-3.5 GB (JVM overhead) |
| Throughput | 1000 req/hour | 1500 req/hour |
| Container Size | ~1.2 GB | ~1.5 GB |

### Optimization Strategies

#### 1. JVM Tuning for Lambda

**Recommended JVM Options:**
```bash
JAVA_TOOL_OPTIONS="-XX:+TieredCompilation \
  -XX:TieredStopAtLevel=1 \
  -XX:+UseSerialGC \
  -Xshare:on \
  -XX:MaxRAMPercentage=80.0 \
  -Dspring.main.lazy-initialization=true \
  -Dspring.backgroundpreinitializer.ignore=true"
```

**Explanation:**
- **TieredCompilation=1**: Faster startup, skip C2 JIT compilation
- **UseSerialGC**: Lower memory overhead for single-threaded Lambda
- **MaxRAMPercentage**: Leave headroom for native memory
- **Lazy initialization**: Defer bean creation until needed

#### 2. Spring Boot Optimization

**application.yml (Lambda profile):**
```yaml
spring:
  profiles:
    active: lambda
  main:
    lazy-initialization: true
    banner-mode: off
  jmx:
    enabled: false
  autoconfigure:
    exclude:
      - org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration
      - org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration

logging:
  level:
    root: WARN
    com.example.emlconverter: INFO
```

#### 3. Playwright Optimization

**Reuse Browser Instance:**
```java
@Component
public class PlaywrightService {

    private Playwright playwright;
    private Browser browser;

    @PostConstruct
    public void init() {
        this.playwright = Playwright.create();
        this.browser = playwright.chromium().launch(new BrowserType.LaunchOptions()
            .setHeadless(true)
            .setArgs(Arrays.asList(
                "--disable-dev-shm-usage",
                "--no-sandbox",
                "--disable-gpu"
            )));
    }

    public byte[] renderPdf(String html) {
        BrowserContext context = browser.newContext();
        Page page = context.newPage();

        try {
            page.setContent(html);
            return page.pdf(new Page.PdfOptions()
                .setFormat("A4")
                .setPrintBackground(true));
        } finally {
            page.close();
            context.close();
        }
    }

    @PreDestroy
    public void cleanup() {
        if (browser != null) browser.close();
        if (playwright != null) playwright.close();
    }
}
```

#### 4. Enable Lambda SnapStart

**Benefits:**
- Reduces cold start from 5s to <1s
- Checkpoints initialized JVM state
- Restores from snapshot on subsequent invocations

**Considerations:**
- Only works with published Lambda versions
- Increases deployment size slightly
- Network connections must be re-established after restore

**Enable:**
```bash
aws lambda update-function-configuration \
  --function-name eml-converter-java-prod \
  --snap-start ApplyOn=PublishedVersions
```

#### 5. Async Processing for Large Batches

**Use SQS for background processing:**
```java
@Service
public class ConversionQueueService {

    private final SqsClient sqsClient;

    public void queueConversion(ConversionRequest request) {
        SendMessageRequest message = SendMessageRequest.builder()
            .queueUrl(queueUrl)
            .messageBody(objectMapper.writeValueAsString(request))
            .build();

        sqsClient.sendMessage(message);
    }
}

@Component
public class ConversionWorker {

    @SqsListener("${aws.sqs.queue.name}")
    public void processConversion(String message) {
        ConversionRequest request = objectMapper.readValue(
            message, ConversionRequest.class
        );

        // Process conversion
        conversionService.convert(request);
    }
}
```

---

## Migration Checklist

### Pre-Migration
- [ ] Audit current Python codebase for all features
- [ ] Document all environment variables and configurations
- [ ] Identify external dependencies (LibreOffice, Playwright, etc.)
- [ ] Review Stripe integration requirements
- [ ] Plan database migration (if using SQLite → PostgreSQL/DynamoDB)
- [ ] Prepare test dataset (sample EML/MSG files)

### Development Phase
- [ ] Set up Java project structure (Maven/Gradle)
- [ ] Configure Spring Boot with all dependencies
- [ ] Implement email parsing (EML and MSG)
- [ ] Implement PDF generation (Playwright-Java)
- [ ] Implement attachment processing
- [ ] Implement S3 integration
- [ ] Implement authentication (JWT)
- [ ] Implement Stripe webhooks
- [ ] Create REST API controllers
- [ ] Write unit tests (>80% coverage)
- [ ] Write integration tests
- [ ] Set up CI/CD pipeline

### Infrastructure
- [ ] Create Dockerfile for Java Lambda
- [ ] Build and test Docker image locally
- [ ] Push image to ECR
- [ ] Update SAM template for Java runtime
- [ ] Deploy to dev environment
- [ ] Run smoke tests
- [ ] Deploy to staging environment
- [ ] Run load tests

### Validation
- [ ] Feature parity testing (compare Python vs Java outputs)
- [ ] Performance benchmarking
- [ ] Security audit
- [ ] Cost analysis (Lambda execution time, memory usage)
- [ ] Documentation updates

### Production Deployment
- [ ] Blue/green deployment setup
- [ ] Deploy Java version to production
- [ ] Monitor CloudWatch metrics
- [ ] Run A/B testing (Python vs Java)
- [ ] Gradual traffic shift to Java version
- [ ] Decommission Python Lambda after validation period

---

## Conclusion

This migration guide provides a comprehensive roadmap for converting the EML/MSG to PDF converter from Python/Flask to Java/Spring Boot. The Java version offers better performance characteristics, especially with Lambda SnapStart, while maintaining feature parity with the current Python implementation.

**Key Takeaways:**
1. **Email Parsing**: Apache Mime4j and MSGParser provide robust email parsing
2. **PDF Generation**: Playwright-Java or Flying Saucer for HTML to PDF rendering
3. **AWS Integration**: AWS SDK v2 for S3, with Spring Cloud AWS for easier integration
4. **Stripe**: stripe-java SDK with Spring Boot webhook handling
5. **Performance**: JVM tuning + SnapStart for sub-second cold starts
6. **Testing**: Comprehensive unit, integration, and E2E testing strategy

**Estimated Migration Timeline:** 8 weeks
**Estimated Migration Cost:** $40,000 - $60,000 (developer time)
**Expected Performance Improvement:** 30-40% faster execution, 60-80% faster cold starts

For questions or assistance with the migration, refer to the code examples and contact the development team.
