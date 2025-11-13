"""
Main CDK Stack for EML/MSG to PDF Converter

Includes:
- DynamoDB table for user management
- Lambda function (containerized with Playwright)
- API Gateway REST API
- CloudFront distribution
- S3 buckets (temp files + frontend hosting)
- Automatic whitelisted user creation
"""

from aws_cdk import (
    Stack,
    Duration,
    RemovalPolicy,
    CfnOutput,
    aws_dynamodb as dynamodb,
    aws_lambda as lambda_,
    aws_apigateway as apigateway,
    aws_s3 as s3,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    aws_sqs as sqs,
    aws_logs as logs,
    aws_ecr as ecr,
    aws_iam as iam,
    custom_resources as cr,
)
from constructs import Construct
import json


class EmlConverterStack(Stack):
    """Main stack for EML converter application"""

    def __init__(self, scope: Construct, construct_id: str, environment: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.environment = environment

        # Create DynamoDB table for user management
        self.users_table = self._create_users_table()

        # Create S3 buckets
        self.temp_bucket = self._create_temp_bucket()
        self.frontend_bucket = self._create_frontend_bucket()

        # Create Dead Letter Queue
        self.dlq = self._create_dlq()

        # Create ECR repository
        self.ecr_repo = self._create_ecr_repository()

        # Create Lambda function
        self.lambda_function = self._create_lambda_function()

        # Create API Gateway
        self.api = self._create_api_gateway()

        # Create CloudFront distribution
        self.distribution = self._create_cloudfront_distribution()

        # Create whitelisted users
        self._create_whitelisted_users()

        # Outputs
        self._create_outputs()

    def _create_users_table(self) -> dynamodb.Table:
        """Create DynamoDB table for user management"""
        table = dynamodb.Table(
            self,
            "UsersTable",
            table_name=f"eml-converter-users-{self.environment}",
            partition_key=dynamodb.Attribute(
                name="email",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.AWS_MANAGED,
            point_in_time_recovery=True,
            stream=dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
            removal_policy=RemovalPolicy.RETAIN if self.environment == "prod" else RemovalPolicy.DESTROY
        )

        # Add Global Secondary Index for user_id
        table.add_global_secondary_index(
            index_name="UserIdIndex",
            partition_key=dynamodb.Attribute(
                name="user_id",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL
        )

        return table

    def _create_temp_bucket(self) -> s3.Bucket:
        """Create S3 bucket for temporary file storage"""
        bucket = s3.Bucket(
            self,
            "TempFilesBucket",
            bucket_name=f"eml-converter-temp-{self.environment}-{self.account}",
            encryption=s3.BucketEncryption.S3_MANAGED,
            versioned=True,
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="DeleteTempFiles",
                    expiration=Duration.days(1),
                    enabled=True
                ),
                s3.LifecycleRule(
                    id="DeleteIncompleteMultipartUploads",
                    abort_incomplete_multipart_upload_after=Duration.days(1),
                    enabled=True
                )
            ],
            cors=[
                s3.CorsRule(
                    allowed_methods=[
                        s3.HttpMethods.GET,
                        s3.HttpMethods.PUT,
                        s3.HttpMethods.POST,
                        s3.HttpMethods.DELETE,
                        s3.HttpMethods.HEAD
                    ],
                    allowed_origins=["*"],
                    allowed_headers=["*"],
                    max_age=3000
                )
            ],
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True
        )

        return bucket

    def _create_frontend_bucket(self) -> s3.Bucket:
        """Create S3 bucket for frontend hosting"""
        bucket = s3.Bucket(
            self,
            "FrontendBucket",
            bucket_name=f"eml-converter-frontend-{self.environment}-{self.account}",
            encryption=s3.BucketEncryption.S3_MANAGED,
            website_index_document="index.html",
            website_error_document="index.html",
            public_read_access=True,
            block_public_access=s3.BlockPublicAccess(
                block_public_acls=False,
                block_public_policy=False,
                ignore_public_acls=False,
                restrict_public_buckets=False
            ),
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True
        )

        return bucket

    def _create_dlq(self) -> sqs.Queue:
        """Create Dead Letter Queue for failed Lambda executions"""
        queue = sqs.Queue(
            self,
            "ProcessingDLQ",
            queue_name=f"eml-converter-dlq-{self.environment}",
            retention_period=Duration.days(14)
        )

        return queue

    def _create_ecr_repository(self) -> ecr.Repository:
        """Create ECR repository for Lambda container image"""
        repo = ecr.Repository(
            self,
            "ECRRepository",
            repository_name=f"eml-converter-{self.environment}",
            lifecycle_rules=[
                ecr.LifecycleRule(
                    description="Keep only the latest 5 images",
                    max_image_count=5,
                    rule_priority=1
                )
            ],
            removal_policy=RemovalPolicy.DESTROY
        )

        return repo

    def _create_lambda_function(self) -> lambda_.Function:
        """Create Lambda function from container image"""
        # Note: The container image must be built and pushed to ECR first
        # Use placeholder for initial deployment, then update with actual image

        function = lambda_.DockerImageFunction(
            self,
            "EmlConverterFunction",
            function_name=f"eml-converter-{self.environment}",
            code=lambda_.DockerImageCode.from_ecr(
                repository=self.ecr_repo,
                tag="latest"
            ),
            memory_size=4096,
            timeout=Duration.minutes(15),
            ephemeral_storage_size=2048,
            environment={
                "S3_BUCKET": self.temp_bucket.bucket_name,
                "ENVIRONMENT": self.environment,
                "PLAYWRIGHT_BROWSERS_PATH": "/var/lang/playwright/browsers",
                "USERS_TABLE": self.users_table.table_name,
                "AWS_REGION_NAME": self.region,
            },
            dead_letter_queue=self.dlq,
            log_retention=logs.RetentionDays.ONE_MONTH
        )

        # Grant permissions
        self.temp_bucket.grant_read_write(function)
        self.users_table.grant_read_write_data(function)

        return function

    def _create_api_gateway(self) -> apigateway.RestApi:
        """Create API Gateway REST API"""
        api = apigateway.RestApi(
            self,
            "EmlConverterAPI",
            rest_api_name=f"eml-converter-api-{self.environment}",
            description=f"EML to PDF Converter API - {self.environment}",
            deploy_options=apigateway.StageOptions(
                stage_name=self.environment,
                logging_level=apigateway.MethodLoggingLevel.INFO,
                data_trace_enabled=True,
                metrics_enabled=True
            ),
            default_cors_preflight_options=apigateway.CorsOptions(
                allow_origins=apigateway.Cors.ALL_ORIGINS,
                allow_methods=apigateway.Cors.ALL_METHODS,
                allow_headers=["*"]
            ),
            binary_media_types=[
                "multipart/form-data",
                "application/pdf",
                "application/zip"
            ]
        )

        # Create Lambda integration
        integration = apigateway.LambdaIntegration(self.lambda_function)

        # API routes
        api_resource = api.root.add_resource("api")

        # POST /api/convert
        convert = api_resource.add_resource("convert")
        convert.add_method("POST", integration)

        # POST /api/upload-url
        upload_url = api_resource.add_resource("upload-url")
        upload_url.add_method("POST", integration)

        # POST /api/convert-s3
        convert_s3 = api_resource.add_resource("convert-s3")
        convert_s3.add_method("POST", integration)

        # GET /api/health
        health = api_resource.add_resource("health")
        health.add_method("GET", integration)

        # Auth endpoints
        auth = api_resource.add_resource("auth")

        # GET /api/auth/check
        auth_check = auth.add_resource("check")
        auth_check.add_method("GET", integration)

        # POST /api/auth/register
        auth_register = auth.add_resource("register")
        auth_register.add_method("POST", integration)

        # POST /api/auth/login
        auth_login = auth.add_resource("login")
        auth_login.add_method("POST", integration)

        # Download endpoints
        # GET /api/download/{session_id}/{filename}
        download = api_resource.add_resource("download")
        session = download.add_resource("{session_id}")
        filename = session.add_resource("{filename}")
        filename.add_method("GET", integration)

        # GET /api/download-all/{session_id}
        download_all = download.add_resource("all")
        download_all_session = download_all.add_resource("{session_id}")
        download_all_session.add_method("GET", integration)

        # GET /api/twemoji/{filename}
        twemoji = api_resource.add_resource("twemoji")
        twemoji_file = twemoji.add_resource("{filename}")
        twemoji_file.add_method("GET", integration)

        return api

    def _create_cloudfront_distribution(self) -> cloudfront.Distribution:
        """Create CloudFront distribution for frontend and API"""
        distribution = cloudfront.Distribution(
            self,
            "CloudFrontDistribution",
            comment=f"EML Converter - {self.environment}",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3Origin(self.frontend_bucket),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                allowed_methods=cloudfront.AllowedMethods.ALLOW_GET_HEAD_OPTIONS,
                cached_methods=cloudfront.CachedMethods.CACHE_GET_HEAD_OPTIONS,
                compress=True,
                cache_policy=cloudfront.CachePolicy.CACHING_OPTIMIZED
            ),
            additional_behaviors={
                "/api/*": cloudfront.BehaviorOptions(
                    origin=origins.RestApiOrigin(self.api),
                    viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                    allowed_methods=cloudfront.AllowedMethods.ALLOW_ALL,
                    cached_methods=cloudfront.CachedMethods.CACHE_GET_HEAD_OPTIONS,
                    cache_policy=cloudfront.CachePolicy.CACHING_DISABLED,
                    origin_request_policy=cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER
                )
            },
            default_root_object="index.html",
            error_responses=[
                cloudfront.ErrorResponse(
                    http_status=404,
                    response_http_status=200,
                    response_page_path="/index.html",
                    ttl=Duration.minutes(5)
                )
            ],
            price_class=cloudfront.PriceClass.PRICE_CLASS_100
        )

        return distribution

    def _create_whitelisted_users(self):
        """Create custom resource to add whitelisted users to DynamoDB"""
        # Load whitelist configuration
        whitelist_config = self._load_whitelist_config()

        if not whitelist_config.get("whitelisted_emails"):
            return

        # Create Lambda function to add users
        user_creator_function = lambda_.Function(
            self,
            "UserCreatorFunction",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="index.handler",
            code=lambda_.Code.from_asset("lambda/user_creator"),
            timeout=Duration.minutes(5),
            environment={
                "USERS_TABLE": self.users_table.table_name,
                "AWS_REGION_NAME": self.region,
            }
        )

        # Grant DynamoDB permissions
        self.users_table.grant_read_write_data(user_creator_function)

        # Create custom resource provider
        provider = cr.Provider(
            self,
            "UserCreatorProvider",
            on_event_handler=user_creator_function
        )

        # Create custom resource
        cr.CustomResource(
            self,
            "WhitelistedUsers",
            service_token=provider.service_token,
            properties={
                "WhitelistedEmails": json.dumps(whitelist_config["whitelisted_emails"]),
                "Environment": self.environment,
                "Timestamp": str(self.node.addr)  # Force update on each deploy
            }
        )

    def _load_whitelist_config(self) -> dict:
        """Load whitelist configuration from file"""
        import os
        config_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "whitelist_config.json"
        )

        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                return json.load(f)

        return {"whitelisted_emails": []}

    def _create_outputs(self):
        """Create CloudFormation outputs"""
        CfnOutput(
            self,
            "APIGatewayURL",
            value=self.api.url,
            description="API Gateway endpoint URL",
            export_name=f"{self.stack_name}-api-url"
        )

        CfnOutput(
            self,
            "CloudFrontURL",
            value=f"https://{self.distribution.domain_name}",
            description="CloudFront distribution URL",
            export_name=f"{self.stack_name}-cloudfront-url"
        )

        CfnOutput(
            self,
            "UsersTableName",
            value=self.users_table.table_name,
            description="DynamoDB users table name",
            export_name=f"{self.stack_name}-users-table"
        )

        CfnOutput(
            self,
            "TempBucketName",
            value=self.temp_bucket.bucket_name,
            description="S3 temporary files bucket",
            export_name=f"{self.stack_name}-temp-bucket"
        )

        CfnOutput(
            self,
            "FrontendBucketName",
            value=self.frontend_bucket.bucket_name,
            description="S3 frontend bucket",
            export_name=f"{self.stack_name}-frontend-bucket"
        )

        CfnOutput(
            self,
            "ECRRepositoryURI",
            value=self.ecr_repo.repository_uri,
            description="ECR repository URI",
            export_name=f"{self.stack_name}-ecr-uri"
        )

        CfnOutput(
            self,
            "LambdaFunctionName",
            value=self.lambda_function.function_name,
            description="Lambda function name",
            export_name=f"{self.stack_name}-lambda-function"
        )
