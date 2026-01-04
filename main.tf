# Create VPC
resource "aws_vpc" "ProdVPC" {
  cidr_block       = var.aws_vpc_cidr
  instance_tenancy = "default"
  tags = {
    Name = "ServerlessVPC"
  }
}
# Create Subnets
resource "aws_subnet" "PublicSubnet1" {
  vpc_id     = aws_vpc.ProdVPC.id
  cidr_block = "10.0.1.0/24"

  tags = {
    Name = "Public Subnet - AZ1"
  }
}
resource "aws_subnet" "AppSubnet1" {
  vpc_id     = aws_vpc.ProdVPC.id
  cidr_block = "10.0.2.0/24"

  tags = {
    Name = "Private subnet - App"
  }
}
resource "aws_subnet" "DBSubnet1" {
  vpc_id     = aws_vpc.ProdVPC.id
  cidr_block = "10.0.3.0/24"

  tags = {
    Name = "Private subnet - DB"
  }
}
resource "aws_subnet" "DBSubnet2" {
  vpc_id            = aws_vpc.ProdVPC.id
  cidr_block        = "10.0.4.0/24"
  availability_zone = "us-west-2b"

  tags = {
    Name = "Private subnet - DB"
  }
}
# Create Internet Gateway
resource "aws_internet_gateway" "ProdIGW" {
  vpc_id = aws_vpc.ProdVPC.id
}
#This is to create Elastic IP for NAT Gateway
resource "aws_eip" "nat" {
  domain = "vpc"
  tags = {
    Name = "Elastic IP for NAT Gateway"
  }
}
#Create NAT Gateway using the above Elastic IP
resource "aws_nat_gateway" "ProdNatGW" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.PublicSubnet1.id

  tags = {
    Name = "GW NAT"
  }
  # To ensure proper ordering, it is recommended to add an explicit dependency
  # on the Internet Gateway for the VPC.
  depends_on = [aws_internet_gateway.ProdIGW]
}
#Public Route Table - to route traffic to Internet Gateway
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.ProdVPC.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.ProdIGW.id
  }
}
#Private Route Table - to route traffic to NAT Gateway
resource "aws_route_table" "PrivateRouteTable" {
  vpc_id = aws_vpc.ProdVPC.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.ProdNatGW.id
  }
}
# Associate Public Subnet with Public Route Table
resource "aws_route_table_association" "PublicSubnet1Association" {
  subnet_id      = aws_subnet.PublicSubnet1.id
  route_table_id = aws_route_table.public.id
}
# Associate App Subnet with Private Route Table
resource "aws_route_table_association" "AppSubnet1Association" {
  subnet_id      = aws_subnet.AppSubnet1.id
  route_table_id = aws_route_table.PrivateRouteTable.id
}
# Associate DB Subnet1 with Private Route Table
resource "aws_route_table_association" "DBSubnet1Association" {
  subnet_id      = aws_subnet.DBSubnet1.id
  route_table_id = aws_route_table.PrivateRouteTable.id
} 
# Associate DB Subnet2 with Private Route Table
resource "aws_route_table_association" "DBSubnet2Association" {
  subnet_id      = aws_subnet.DBSubnet2.id
  route_table_id = aws_route_table.PrivateRouteTable.id
}
#Security Group for DB Instance
resource "aws_security_group" "DB_SG" {
  name        = "DB_SG"
  description = "Security group for RDS instance"
  vpc_id      = aws_vpc.ProdVPC.id

  tags = {
    Name = "DB Security Group"
  }
}
# RDS Engress: Allow RDS to respond back to any ephemeral port 
resource "aws_vpc_security_group_egress_rule" "AllowAllOutbound" {
  security_group_id = aws_security_group.DB_SG.id

  cidr_ipv4   = aws_vpc.ProdVPC.cidr_block
  from_port   = 0     # Start of port range  
  to_port     = 65535 # End of port range
  ip_protocol = "tcp"
}
#Ingress rule to allow inbound traffic from Lambda SG to Inbound SG on port 3306
resource "aws_vpc_security_group_ingress_rule" "inbound_traffic" {
  security_group_id = aws_security_group.DB_SG.id

  referenced_security_group_id = aws_security_group.lambdaSG.id
  from_port                    = 3306
  ip_protocol                  = "tcp"
  to_port                      = 3306
}
# Create RDS Instance
resource "aws_db_instance" "MyDBInstance" {
  allocated_storage      = 10      #size in GB 
  db_name                = "mydb"  #name of database 
  engine                 = "mysql" #type of database 
  engine_version         = "8.0"   #version of database
  instance_class         = "db.t3.micro"
  username               = var.DB_USER
  password               = var.DB_PASSWORD
  parameter_group_name   = "default.mysql8.0"
  skip_final_snapshot    = true
  vpc_security_group_ids = [aws_security_group.DB_SG.id]
  db_subnet_group_name   = aws_db_subnet_group.MainDBSubnetGroup.name
  publicly_accessible    = false #Keep RDS instance private
}
# Create DB Subnet Group
resource "aws_db_subnet_group" "MainDBSubnetGroup" {
  name       = "main"
  subnet_ids = [aws_subnet.DBSubnet1.id, aws_subnet.DBSubnet2.id]
}
# Security Group for Lambda Function
resource "aws_security_group" "lambdaSG" {
  name        = "lambda_sg"
  description = "Allow lambda functions to access resources in VPC"
  vpc_id      = aws_vpc.ProdVPC.id

  tags = {
    Name = "Lambda Security Group"
  }
}
# Egress rule to allow all outbound traffic from Lambda SG
resource "aws_vpc_security_group_egress_rule" "allow_all_outbound_traffic_from_lambda" {
  security_group_id = aws_security_group.lambdaSG.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1" # semantically equivalent to all ports
}
# Create IAM Role for Lambda
resource "aws_iam_role" "lambda_role" {
  name = "lambda_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = "AllowLambdaAssumeRole"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}
# Attach the AWSLambdaBasicExecutionRole managed policy to the role
resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
} 
# Create Lambda Function
resource "aws_lambda_function" "Prod_Lambda" {
  filename         = "lambda_package.zip"
  function_name    = "Production_lambda_function"
  role             = aws_iam_role.lambda_role.arn
  handler          = "test_db_connection.lambda_handler"
  source_code_hash = filebase64sha256("lambda_package.zip")
  runtime          = "python3.9"
  environment {
    variables = {
      db_secret = aws_secretsmanager_secret.rds_db_credentials_v2.arn

    }
  }
  vpc_config {
    subnet_ids         = [aws_subnet.AppSubnet1.id]
    security_group_ids = [aws_security_group.lambdaSG.id]
  }
}
# Create KMS Key for Secrets Manager
resource "aws_kms_key" "my_kms_key" {
  description             = "An example symmetric encryption KMS key"
  enable_key_rotation     = true
  deletion_window_in_days = 7
}
# Create KMS Alias
resource "aws_kms_alias" "my_kms_alias" {
  name          = "alias/myKeyAlias"
  target_key_id = aws_kms_key.my_kms_key.id
}
# Create Secrets Manager Secret to store RDS credentials
resource "aws_secretsmanager_secret" "rds_db_credentials_v2" {
  name                    = "rds-db-credentials-v2"
  description             = "RDS DB Credentials"
  kms_key_id              = aws_kms_key.my_kms_key.arn
  recovery_window_in_days = 0
}
# Create Secret Version with RDS credentials
resource "aws_secretsmanager_secret_version" "rds_db_credentials_version" {
  secret_id = aws_secretsmanager_secret.rds_db_credentials_v2.id
  secret_string = jsonencode({
    user     = var.DB_USER
    password = var.DB_PASSWORD
    host     = aws_db_instance.MyDBInstance.address
    port     = var.DB_PORT
    database = var.DB_NAME
  })
}
# Policy to allow Lambda to access Secrets Manager and Decrypt KMS
resource "aws_iam_policy" "lambda_secretsmanager_policy" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = aws_secretsmanager_secret.rds_db_credentials_v2.arn
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = aws_kms_key.my_kms_key.arn
      }
    ]
  })
}
# Attach the above policy to Lambda Role
resource "aws_iam_role_policy_attachment" "attach_lambda_secretsmanager_policy" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_secretsmanager_policy.arn
}
#API Gateway to trigger Lambda
resource "aws_apigatewayv2_api" "http_api" {
  name          = "http_api"
  protocol_type = "HTTP"
  disable_execute_api_endpoint = true
}
# Integration of API Gateway with Lambda
resource "aws_apigatewayv2_integration" "lambda_integration" {
  api_id             = aws_apigatewayv2_api.http_api.id
  integration_type   = "AWS_PROXY"
  integration_uri    = aws_lambda_function.Prod_Lambda.arn
  integration_method = "POST"
  payload_format_version = "2.0"
}
# API Gateway Route to trigger Lambda
resource "aws_apigatewayv2_route" "lambda_route" {
  api_id    = aws_apigatewayv2_api.http_api.id
  route_key = "GET /testdb"
  target    = "integrations/${aws_apigatewayv2_integration.lambda_integration.id}"
} 
# Cognito user pool for authentication
resource "aws_cognito_user_pool" "user_pool" {
  name = "serverless-api-user-pool"

  # Password policy
  password_policy {
    minimum_length    = 8
    require_uppercase = true
    require_lowercase = true
    require_numbers   = true
    require_symbols   = true  
  }
  # Account recovery settings
  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1    
    }
  }
  # Email Verification 
  auto_verified_attributes = ["email"]
  username_attributes = ["email"]
  #Email configuration using Cognito default email sender
  email_configuration {
    email_sending_account = "COGNITO_DEFAULT"
  }
  schema {
    attribute_data_type      = "String"
    name                     = "email"
    required                 = true
    mutable                  = false
  } 
  # MFA configuration
  mfa_configuration = "OPTIONAL"
  software_token_mfa_configuration {
    enabled = true
  }
}
# Cognito user pool client
resource "aws_cognito_user_pool_client" "user_pool_client" {
  name         = "serverless-api-user-pool-client"
  user_pool_id = aws_cognito_user_pool.user_pool.id
  explicit_auth_flows = [
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
    "ALLOW_USER_SRP_AUTH"
  ]
}
# API Gateway Authorizer for Cognito
resource "aws_apigatewayv2_authorizer" "cognito_authorizer" {
  name = "cognito_authorizer"
  api_id      = aws_apigatewayv2_api.http_api.id
  authorizer_type = "JWT"
  identity_sources = ["$request.header.Authorization"]
  jwt_configuration {
    audience = [aws_cognito_user_pool_client.user_pool_client.id]
    issuer   = "https://${aws_cognito_user_pool.user_pool.endpoint}"
  }
}
# Update API Gateway Route to use Cognito Authorizer
resource "aws_apigatewayv2_route" "lambda_route_with_auth" {
  api_id    = aws_apigatewayv2_api.http_api.id
  route_key = "GET /testdb"
  target    = "integrations/${aws_apigatewayv2_integration.lambda_integration.id}"
  authorizer_id = aws_apigatewayv2_authorizer.cognito_authorizer.id
  authorization_type = "JWT"
}
# cloudfront in front of api gateway
resource "aws_cloudfront_distribution" "api_distribution" {
  web_acl_id = aws_wafv2_web_acl.api_waf.arn
  origin {
    domain_name =  trimprefix( trimsuffix(aws_apigatewayv2_api.http_api.api_endpoint, "/"), "https://")
    origin_id   = "api-gateway-origin"  
    origin_path = ""
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  } 
  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = ""
  default_cache_behavior {
    target_origin_id       = "api-gateway-origin"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD", "OPTIONS"]
    forwarded_values {
      query_string = true   
      cookies {
        forward = "none"
      }
    }
    min_ttl                = 0
    default_ttl            = 0
    max_ttl                = 0
  }
  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
  viewer_certificate {
    cloudfront_default_certificate = true
  }
}
# WAFv2 Web ACL
resource "aws_wafv2_web_acl" "api_waf" {
  name        = "api-waf"
  description = "WAF for API Gateway"
  scope       = "CLOUDFRONT"
  region      = "us-east-1"
  default_action {
    allow {}
  }
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "apiWAF"
    sampled_requests_enabled   = true
  }
}
# WAFv2 Rule Group with basic rules
resource "aws_wafv2_rule_group" "basic_rules" {
  name        = "basic-rules"
  description = "Basic rules for WAF"
  scope       = "CLOUDFRONT"
  capacity    = 50
  region = "us-east-1"

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "basicRules"
    sampled_requests_enabled   = true
  }
  rule {
    name     = "LimitRequests100"
    priority = 1
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = 100
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "LimitRequests100"
      sampled_requests_enabled   = true
    }
  }
}
# CloudWatch Log Group for Lambda
resource "aws_cloudwatch_log_group" "lambda_log_group" {
  name              = "/aws/lambda/${aws_lambda_function.Prod_Lambda.function_name}"
  retention_in_days = 14
}
# CloudWatch Log Group for API Gateway
resource "aws_cloudwatch_log_group" "api_gw_log_group" {
  name              = "/aws/apigateway/${aws_apigatewayv2_api.http_api.name}"
  retention_in_days = 14
} 
# Grant API Gateway permission to write to CloudWatch Logs
resource "aws_iam_role" "api_gw_cloudwatch_role" {
  name = "api_gw_cloudwatch_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "apigateway.amazonaws.com"
        }
      }
    ]
  })  
  tags = {
    tag-key = "tag-value"
  }
}
# Attach policy to allow writing logs to CloudWatch
resource "aws_iam_role_policy_attachment" "api_gw_cloudwatch_policy_attach" {
  role       = aws_iam_role.api_gw_cloudwatch_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
}
# Cloudwatch Alarm for Lambda Errors
resource "aws_cloudwatch_metric_alarm" "lambda_error_alarm" {
  alarm_name          = "LambdaErrorAlarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Alarm when the Lambda function has errors"
  dimensions = {
    FunctionName = aws_lambda_function.Prod_Lambda.function_name
  }
}
# Cloudwatch Alarm for API Gateway 5XX Errors
resource "aws_cloudwatch_metric_alarm" "api_gw_5xx_alarm" {
  alarm_name          = "APIGateway5XXErrorAlarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "5XXError"
  namespace           = "AWS/ApiGateway"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Alarm when the API Gateway has 5XX errors"
  dimensions = {
    ApiName = aws_apigatewayv2_api.http_api.name
  }
}   
# CloudWatch Alarm for RDS CPU Utilization
resource "aws_cloudwatch_metric_alarm" "rds_cpu_utilization_alarm" {
  alarm_name          = "RDSCPUUtilizationAlarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 300   
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Alarm when RDS CPU Utilization exceeds 80%"
  dimensions = {
    DBInstanceIdentifier = aws_db_instance.MyDBInstance.id
  }
} 
# CloudWatch Dashboard
resource "aws_cloudwatch_dashboard" "serverless_api_dashboard" {
  dashboard_name = "ServerlessAPIDashboard"
  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric"
        x    = 0
        y    = 0
        width = 12
        height = 6
        properties = {
          metrics = [
            [ "AWS/Lambda", "Errors", "FunctionName", aws_lambda_function.Prod_Lambda.function_name ],
            [ ".", "Invocations", ".", "." ]
          ]
          title = "Lambda Function Errors and Invocations"
          view  = "timeSeries"
          stacked = false
          region = var.aws_region
          period = 300
        }
      },
      {
        type = "metric"
        x    = 12
        y    = 0
        width = 12
        height = 6
        properties = {          
          metrics = [
            [ "AWS/ApiGateway", "5XXError", "ApiName", aws_apigatewayv2_api.http_api.name ],
            [ ".", "4XXError", ".", "." ]
          ]
          title = "API Gateway 4XX and 5XX Errors"
          view  = "timeSeries"
          stacked = false
          region = var.aws_region
          period = 300
        }
      },
      {
        type = "metric"         
        x    = 0
        y    = 6      
        width = 12
        height = 6
        properties = {          
          metrics = [
            [ "AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", aws_db_instance.MyDBInstance.id ]
          ]
          title = "RDS CPU Utilization"
          view  = "timeSeries"
          stacked = false
          region = var.aws_region
          period = 300  
        }
      }
    ] 
  })
} 
