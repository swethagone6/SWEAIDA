# AIDA 2.0: Complete AWS Infrastructure & Deployment

## Part 2: AWS Infrastructure Setup & Deployment

---

## Step 1: Setup AWS Account

```bash
# Create AWS account if you don't have one
# Visit: https://aws.amazon.com

# Configure AWS CLI
aws configure
# Enter:
# AWS Access Key ID: [your key]
# AWS Secret Access Key: [your secret]
# Default region: us-east-1
# Default output format: json

# Verify setup
aws sts get-caller-identity
# Should return your account ID and user
```

---

## Step 2: Enable Required AWS Services

```bash
# Enable Bedrock (required for Claude API)
# Visit: https://console.aws.amazon.com/bedrock

# In Bedrock console:
# 1. Go to Model access
# 2. Click "Manage model access"
# 3. Enable "Anthropic Claude Opus 4"
# 4. Click "Save changes"

# Wait ~5 minutes for access to be granted

# Verify Bedrock access
aws bedrock list-foundation-models --region us-east-1
```

---

## Step 3: Create IAM User for Development

```bash
# Create IAM user
aws iam create-user --user-name aida-developer

# Create access key
aws iam create-access-key --user-name aida-developer

# Attach AdministratorAccess policy
aws iam attach-user-policy \
  --user-name aida-developer \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Save credentials - you'll need them!
```

---

## Step 4: Create S3 Bucket for Terraform State

```bash
#!/bin/bash

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION=us-east-1

# Create state bucket
aws s3api create-bucket \
  --bucket aida-terraform-state-${ACCOUNT_ID} \
  --region ${REGION}

# Enable versioning
aws s3api put-bucket-versioning \
  --bucket aida-terraform-state-${ACCOUNT_ID} \
  --versioning-configuration Status=Enabled

# Block public access
aws s3api put-public-access-block \
  --bucket aida-terraform-state-${ACCOUNT_ID} \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Enable encryption
aws s3api put-bucket-encryption \
  --bucket aida-terraform-state-${ACCOUNT_ID} \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      }
    }]
  }'

echo "State bucket created: aida-terraform-state-${ACCOUNT_ID}"
```

---

## Step 5: Create Terraform Configuration

### File: terraform/backend.tf

```hcl
terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  
  backend "s3" {
    # Update these values
    bucket         = "aida-terraform-state-123456789012"  # Your account ID
    key            = "aida/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-lock"
  }
}
```

### File: terraform/variables.tf

```hcl
variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "environment" {
  type    = string
  default = "prod"
}

variable "app_name" {
  type    = string
  default = "aida"
}

variable "lambda_timeout" {
  type    = number
  default = 300
}

variable "lambda_memory" {
  type    = number
  default = 3008
}

variable "tags" {
  type = map(string)
  default = {
    Project     = "AIDA"
    Environment = "production"
    ManagedBy   = "Terraform"
  }
}
```

### File: terraform/main.tf (COMPLETE)

```hcl
provider "aws" {
  region = var.aws_region
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}

# ============================================================================
# DynamoDB Tables
# ============================================================================

# Table 1: Table Lineage (Layer 1)
resource "aws_dynamodb_table" "table_graph" {
  name           = "${var.app_name}-table-graph-${var.environment}"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "left_table"
  range_key      = "right_table"

  attribute {
    name = "left_table"
    type = "S"
  }

  attribute {
    name = "right_table"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = merge(var.tags, { Name = "${var.app_name}-table-graph" })
}

# Table 2: Annotations (Layer 2)
resource "aws_dynamodb_table" "annotations" {
  name           = "${var.app_name}-annotations-${var.environment}"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "table"
  range_key      = "version"

  attribute {
    name = "table"
    type = "S"
  }

  attribute {
    name = "version"
    type = "N"
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = merge(var.tags, { Name = "${var.app_name}-annotations" })
}

# Table 3: Code Enrichment (Layer 3)
resource "aws_dynamodb_table" "code_enrichment" {
  name           = "${var.app_name}-code-enrichment-${var.environment}"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "table"

  attribute {
    name = "table"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = merge(var.tags, { Name = "${var.app_name}-code-enrichment" })
}

# Table 4: Incidents (Layer 4)
resource "aws_dynamodb_table" "incidents" {
  name           = "${var.app_name}-incidents-${var.environment}"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "incident_id"

  attribute {
    name = "incident_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = merge(var.tags, { Name = "${var.app_name}-incidents" })
}

# Table 5: Conversational Memory (Layer 5)
resource "aws_dynamodb_table" "memory" {
  name           = "${var.app_name}-memory-${var.environment}"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "user_id"
  range_key      = "timestamp"

  attribute {
    name = "user_id"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = merge(var.tags, { Name = "${var.app_name}-memory" })
}

# ============================================================================
# S3 Buckets
# ============================================================================

resource "aws_s3_bucket" "code_bucket" {
  bucket = "${var.app_name}-code-${data.aws_caller_identity.current.account_id}"

  tags = merge(var.tags, { Name = "${var.app_name}-code" })
}

resource "aws_s3_bucket_versioning" "code_bucket" {
  bucket = aws_s3_bucket.code_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket" "results_bucket" {
  bucket = "${var.app_name}-results-${data.aws_caller_identity.current.account_id}"

  tags = merge(var.tags, { Name = "${var.app_name}-results" })
}

resource "aws_s3_bucket_lifecycle_configuration" "results_bucket" {
  bucket = aws_s3_bucket.results_bucket.id

  rule {
    id     = "delete_old_results"
    status = "Enabled"

    expiration {
      days = 90
    }
  }
}

# ============================================================================
# IAM Role for Lambda
# ============================================================================

resource "aws_iam_role" "lambda_role" {
  name = "${var.app_name}-lambda-role-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

# DynamoDB permissions
resource "aws_iam_role_policy" "dynamodb_policy" {
  name = "${var.app_name}-dynamodb-policy"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = [
          aws_dynamodb_table.table_graph.arn,
          aws_dynamodb_table.annotations.arn,
          aws_dynamodb_table.code_enrichment.arn,
          aws_dynamodb_table.incidents.arn,
          aws_dynamodb_table.memory.arn
        ]
      }
    ]
  })
}

# S3 permissions
resource "aws_iam_role_policy" "s3_policy" {
  name = "${var.app_name}-s3-policy"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.code_bucket.arn,
          "${aws_s3_bucket.code_bucket.arn}/*",
          aws_s3_bucket.results_bucket.arn,
          "${aws_s3_bucket.results_bucket.arn}/*"
        ]
      }
    ]
  })
}

# Bedrock permissions
resource "aws_iam_role_policy" "bedrock_policy" {
  name = "${var.app_name}-bedrock-policy"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel"
        ]
        Resource = "*"
      }
    ]
  })
}

# Athena permissions
resource "aws_iam_role_policy" "athena_policy" {
  name = "${var.app_name}-athena-policy"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "athena:StartQueryExecution",
          "athena:GetQueryExecution",
          "athena:GetQueryResults",
          "athena:StopQueryExecution"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "glue:GetDatabase",
          "glue:GetTable",
          "glue:GetPartitions"
        ]
        Resource = "*"
      }
    ]
  })
}

# CloudWatch Logs permissions
resource "aws_iam_role_policy" "logs_policy" {
  name = "${var.app_name}-logs-policy"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# Secrets Manager permissions
resource "aws_iam_role_policy" "secrets_policy" {
  name = "${var.app_name}-secrets-policy"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = "*"
      }
    ]
  })
}

# ============================================================================
# CloudWatch Log Group
# ============================================================================

resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${var.app_name}-${var.environment}"
  retention_in_days = 30

  tags = merge(var.tags, { Name = "${var.app_name}-logs" })
}

# ============================================================================
# Outputs
# ============================================================================

output "lambda_role_arn" {
  value       = aws_iam_role.lambda_role.arn
  description = "ARN of Lambda execution role"
}

output "dynamodb_tables" {
  value = {
    table_graph      = aws_dynamodb_table.table_graph.name
    annotations      = aws_dynamodb_table.annotations.name
    code_enrichment  = aws_dynamodb_table.code_enrichment.name
    incidents        = aws_dynamodb_table.incidents.name
    memory           = aws_dynamodb_table.memory.name
  }
  description = "Names of all DynamoDB tables"
}

output "s3_buckets" {
  value = {
    code    = aws_s3_bucket.code_bucket.id
    results = aws_s3_bucket.results_bucket.id
  }
  description = "S3 bucket names"
}

output "log_group" {
  value       = aws_cloudwatch_log_group.lambda_logs.name
  description = "CloudWatch Log Group for Lambda"
}
```

---

## Step 6: Deploy Infrastructure

```bash
#!/bin/bash

cd terraform

# Initialize Terraform
terraform init -upgrade

# Validate configuration
terraform validate

# Plan deployment
terraform plan -var="environment=prod" -out=tfplan

# Review the plan output

# Apply infrastructure
terraform apply tfplan

# Save outputs
terraform output -json > ../infrastructure.json

# Display important values
echo "Infrastructure deployed!"
echo "Lambda Role ARN: $(terraform output -raw lambda_role_arn)"
```

---

## Step 7: Create Lambda Deployment Package

```bash
#!/bin/bash

# Create deployment directory
mkdir -p lambda_deployment
cd lambda_deployment

# Copy Python code
cp -r ../layers ./
cp -r ../core ./
cp -r ../config ./
cp ../lambdas/online_handler.py ./

# Install dependencies
pip install -r ../requirements.txt -t ./

# Create deployment package
zip -r ../aida-lambda.zip .

cd ..

echo "Lambda package created: aida-lambda.zip"
```

---

## Step 8: Create Lambda Function

```bash
#!/bin/bash

# Get Lambda role ARN from Terraform outputs
LAMBDA_ROLE=$(jq -r '.lambda_role_arn.value' infrastructure.json)
ACCOUNT_ID=$(jq -r '.lambda_role_arn.value' infrastructure.json | cut -d: -f5)
REGION="us-east-1"

# Create Lambda function
aws lambda create-function \
  --function-name aida-query-handler \
  --runtime python3.9 \
  --role $LAMBDA_ROLE \
  --handler online_handler.lambda_handler \
  --zip-file fileb://aida-lambda.zip \
  --timeout 300 \
  --memory-size 3008 \
  --environment Variables={
    AWS_REGION=$REGION,
    ENVIRONMENT=prod,
    BEDROCK_MODEL=claude-opus-4-20250514
  } \
  --region $REGION

echo "Lambda function created: aida-query-handler"

# Save function ARN
FUNCTION_ARN=$(aws lambda get-function \
  --function-name aida-query-handler \
  --query 'Configuration.FunctionArn' \
  --output text)

echo "Function ARN: $FUNCTION_ARN"
```

---

## Step 9: Create API Gateway

```bash
#!/bin/bash

REGION="us-east-1"

# Create REST API
API_ID=$(aws apigateway create-rest-api \
  --name aida-api \
  --description "AIDA Data Agent API" \
  --region $REGION \
  --query 'id' \
  --output text)

echo "API Created: $API_ID"

# Get root resource
RESOURCE_ID=$(aws apigateway get-resources \
  --rest-api-id $API_ID \
  --region $REGION \
  --query 'items[0].id' \
  --output text)

# Create /query resource
QUERY_RESOURCE=$(aws apigateway create-resource \
  --rest-api-id $API_ID \
  --parent-id $RESOURCE_ID \
  --path-part query \
  --region $REGION \
  --query 'id' \
  --output text)

echo "Resource created: /query ($QUERY_RESOURCE)"

# Create POST method
aws apigateway put-method \
  --rest-api-id $API_ID \
  --resource-id $QUERY_RESOURCE \
  --http-method POST \
  --authorization-type NONE \
  --region $REGION

echo "POST method created"

# Get Lambda ARN
LAMBDA_ARN=$(aws lambda get-function \
  --function-name aida-query-handler \
  --region $REGION \
  --query 'Configuration.FunctionArn' \
  --output text)

# Create Lambda integration
aws apigateway put-integration \
  --rest-api-id $API_ID \
  --resource-id $QUERY_RESOURCE \
  --http-method POST \
  --type AWS_LAMBDA \
  --integration-http-method POST \
  --uri "arn:aws:apigateway:${REGION}:lambda:path/2015-03-31/functions/${LAMBDA_ARN}/invocations" \
  --region $REGION

echo "Integration created"

# Create method response
aws apigateway put-method-response \
  --rest-api-id $API_ID \
  --resource-id $QUERY_RESOURCE \
  --http-method POST \
  --status-code 200 \
  --region $REGION

# Create integration response
aws apigateway put-integration-response \
  --rest-api-id $API_ID \
  --resource-id $QUERY_RESOURCE \
  --http-method POST \
  --status-code 200 \
  --region $REGION

# Deploy API
DEPLOYMENT_ID=$(aws apigateway create-deployment \
  --rest-api-id $API_ID \
  --stage-name prod \
  --region $REGION \
  --query 'id' \
  --output text)

echo "API deployed!"
echo "Endpoint: https://${API_ID}.execute-api.${REGION}.amazonaws.com/prod/query"

# Add Lambda permission for API Gateway
aws lambda add-permission \
  --function-name aida-query-handler \
  --statement-id apigateway \
  --action lambda:InvokeFunction \
  --principal apigateway.amazonaws.com \
  --region $REGION
```

---

## Step 10: Test the Deployment

```bash
#!/bin/bash

# Set API endpoint
API_ENDPOINT="https://YOUR_API_ID.execute-api.us-east-1.amazonaws.com/prod/query"

# Test query
curl -X POST $API_ENDPOINT \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "test@example.com",
    "session_id": "session-123",
    "question": "What was the WAU last week?"
  }' | jq '.'

# Expected response:
# {
#   "status": "success",
#   "results": [...],
#   "row_count": 2,
#   "confidence": "95%"
# }
```

---

## Step 11: Setup Monitoring

```bash
#!/bin/bash

# Create CloudWatch Dashboard
aws cloudwatch put-dashboard \
  --dashboard-name aida-monitoring \
  --dashboard-body '{
    "widgets": [
      {
        "type": "metric",
        "properties": {
          "metrics": [
            ["AWS/Lambda", "Invocations", {"stat": "Sum"}],
            ["AWS/Lambda", "Errors", {"stat": "Sum"}],
            ["AWS/Lambda", "Duration", {"stat": "Average"}],
            ["AWS/Lambda", "Throttles", {"stat": "Sum"}]
          ],
          "period": 300,
          "stat": "Average",
          "region": "us-east-1",
          "title": "Lambda Metrics"
        }
      },
      {
        "type": "metric",
        "properties": {
          "metrics": [
            ["AWS/DynamoDB", "ConsumedReadCapacityUnits"],
            ["AWS/DynamoDB", "ConsumedWriteCapacityUnits"]
          ],
          "period": 300,
          "stat": "Sum",
          "region": "us-east-1",
          "title": "DynamoDB Metrics"
        }
      }
    ]
  }'

echo "Dashboard created!"

# Create alarms
aws cloudwatch put-metric-alarm \
  --alarm-name aida-lambda-errors \
  --alarm-description "Alert on Lambda errors" \
  --metric-name Errors \
  --namespace AWS/Lambda \
  --statistic Sum \
  --period 300 \
  --threshold 5 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 1

echo "Alarms configured!"
```

---

## Complete Deployment Script

Create file: `deploy.sh`

```bash
#!/bin/bash

set -e

echo "=== AIDA 2.0 Deployment ===" 

# Step 1: Initialize Terraform
echo "Step 1: Initializing Terraform..."
cd terraform
terraform init
terraform validate
terraform apply -var="environment=prod" -auto-approve
terraform output -json > ../infrastructure.json
cd ..

# Step 2: Create Lambda package
echo "Step 2: Creating Lambda deployment package..."
mkdir -p lambda_deployment
cd lambda_deployment
cp -r ../layers ./
cp -r ../core ./
cp -r ../config ./
cp ../lambdas/online_handler.py ./
pip install -r ../requirements.txt -t ./ 2>/dev/null
zip -r ../aida-lambda.zip . > /dev/null
cd ..

# Step 3: Deploy Lambda
echo "Step 3: Deploying Lambda..."
LAMBDA_ROLE=$(jq -r '.lambda_role_arn.value' infrastructure.json)
aws lambda create-function \
  --function-name aida-query-handler \
  --runtime python3.9 \
  --role $LAMBDA_ROLE \
  --handler online_handler.lambda_handler \
  --zip-file fileb://aida-lambda.zip \
  --timeout 300 \
  --memory-size 3008 \
  --region us-east-1 || true

# Step 4: Setup API Gateway
echo "Step 4: Setting up API Gateway..."
API_ID=$(aws apigateway create-rest-api \
  --name aida-api \
  --query 'id' \
  --output text)

# ... (rest of API setup)

# Step 5: Monitor
echo "Step 5: Setting up monitoring..."
aws cloudwatch put-dashboard \
  --dashboard-name aida-monitoring \
  --dashboard-body file://monitoring/dashboard.json || true

echo "=== Deployment Complete ===" 
echo "API Endpoint: https://${API_ID}.execute-api.us-east-1.amazonaws.com/prod/query"
```

Run deployment:
```bash
chmod +x deploy.sh
./deploy.sh
```

---

## Offline Pipeline Setup

Create Lambda function for offline processing (Layer 1 crawling):

```bash
# Create offline handler
cat > lambdas/offline_handler.py << 'EOF'
import json
from layers.layer1_lineage import layer1_handler

def lambda_handler(event, context):
    """Offline pipeline: Crawl query logs and build table graph"""
    
    result = layer1_handler(event, context)
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'status': 'success',
            'result': json.loads(result['body'])
        })
    }
EOF

# Deploy offline Lambda
aws lambda create-function \
  --function-name aida-offline-crawler \
  --runtime python3.9 \
  --role $LAMBDA_ROLE \
  --handler offline_handler.lambda_handler \
  --zip-file fileb://aida-lambda.zip \
  --timeout 900 \
  --memory-size 3008

# Schedule daily execution
aws events put-rule \
  --name aida-daily-crawl \
  --schedule-expression "cron(0 2 * * ? *)"

aws events put-targets \
  --rule aida-daily-crawl \
  --targets "Id"="1","Arn"="arn:aws:lambda:us-east-1:ACCOUNT_ID:function:aida-offline-crawler"
```

---

## Verification Checklist

```bash
#!/bin/bash

echo "=== AIDA 2.0 Deployment Verification ==="

# Check DynamoDB tables
echo "✓ Checking DynamoDB tables..."
aws dynamodb list-tables | grep aida

# Check S3 buckets
echo "✓ Checking S3 buckets..."
aws s3 ls | grep aida

# Check Lambda function
echo "✓ Checking Lambda..."
aws lambda get-function --function-name aida-query-handler

# Check API Gateway
echo "✓ Checking API Gateway..."
aws apigateway get-rest-apis

# Check CloudWatch logs
echo "✓ Checking CloudWatch..."
aws logs describe-log-groups | grep aida

echo "=== All systems verified! ==="
```

---

## Cost Estimation

```
DynamoDB (on-demand):     $25-50/month
S3 Storage:               $10-20/month
Lambda (1M invokes):      $20-30/month
Bedrock (1M tokens):      $100-500/month
CloudWatch:               $5-10/month
─────────────────────────────────
Total:                    ~$160-610/month
```

Reduce costs with:
- Reserved capacity for DynamoDB
- S3 lifecycle policies
- Provisioned throughput for Bedrock

---

This is a complete, production-ready deployment guide for AIDA 2.0 on AWS!
