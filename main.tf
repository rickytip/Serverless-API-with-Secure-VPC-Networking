resource "aws_vpc" "ProdVPC" {
  cidr_block = var.aws_vpc_cidr
  instance_tenancy = "default"
  tags = {
    Name = "ServerlessVPC"
  }
} 
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
  vpc_id     = aws_vpc.ProdVPC.id
  cidr_block = "10.0.4.0/24"
  availability_zone = "us-west-2b"

  tags = {
    Name = "Private subnet - DB"
  }
}
resource "aws_internet_gateway" "ProdIGW" {
  vpc_id = aws_vpc.ProdVPC.id
}
#This is to create Elastic IP for NAT Gateway
resource "aws_eip" "nat" {
  domain   = "vpc"
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
    cidr_block = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.ProdNatGW.id
    }
}
#Security Group for RDS Instance
resource "aws_security_group" "RDS_SG" {
  name        = "RDS_SG"
  description = "Security group for RDS instance"
  vpc_id      = aws_vpc.ProdVPC.id

  tags = {
    Name = "RDS Security Group"
  }
}
# RDS Engress: Allow RDS to respond back to any ephemeral port 
resource "aws_vpc_security_group_egress_rule" "AllowAllOutbound" {
  security_group_id = aws_security_group.RDS_SG.id

  cidr_ipv4 = aws_vpc.ProdVPC.cidr_block
  from_port   = 0 # Start of port range  
  to_port     = 65535 # End of port range
  ip_protocol = "tcp"
}
#Ingress rule to allow inbound traffic from Lambda SG to Inbound SG on port 3306
resource "aws_vpc_security_group_ingress_rule" "inbound_traffic" {
  security_group_id = aws_security_group.RDS_SG.id

  referenced_security_group_id = aws_security_group.lambdaSG.id
  from_port   = 3306
  ip_protocol = "tcp"
  to_port     = 3306
}
# Create RDS Instance
resource "aws_db_instance" "MyRDSInstance" {
  allocated_storage    = 10 #size in GB 
  db_name              = "mydb" #name of database 
  engine               = "mysql" #type of database 
  engine_version       = "8.0" #version of database
  instance_class       = "db.t3.micro" 
  username             = var.db_username
  password             = var.db_password
  parameter_group_name = "default.mysql8.0"
  skip_final_snapshot  = true
  vpc_security_group_ids = aws_security_group.RDS_SG.id
  publicly_accessible = false #Keep RDS instance private
}
# Create DB Subnet Group
resource "aws_db_subnet_group" "MainDBSubnetGroup" {
  name       = "main"
  subnet_ids = [aws_subnet.DBSubnet1.id, aws_subnet.DBSubnet2.id]
}
resource "aws_security_group" "lambdaSG" {
  name        = "lambda_sg"
  description = "Allow lambda functions to access resources in VPC"
  vpc_id      = aws_vpc.ProdVPC.id

  tags = {
    Name = "Lambda Security Group"
  }
}
resource "aws_vpc_security_group_egress_rule" "allow_all_outbound_traffic_from_lambda" {
  security_group_id = aws_security_group.allow_lambda_traffic.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1" # semantically equivalent to all ports
}  
resource "aws_iam_role" "lambda role" {
  name = "lambda_role"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      },
    ]
  })

  tags = {
    tag-key = "tag-value"
  }
}
# Attach the AWSLambdaVPCAccessExecutionRole managed policy to the role
resource "aws_iam_role_policy_attachment" "CloudWatch_logs" {
  role       = aws_iam_role.lambda role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}
# Create Lambda Function
resource "aws_lambda_function" "Prod_Lambda" {
  filename         = data.archive_file.example.output_path
  function_name    = "Production_lambda_function"
  role             = aws_iam_role.lambda role.arn 
  handler          = "index.handler"
  source_code_hash = data.archive_file.example.output_base64sha2
  runtime          = "python3.9"
  enviroment {
    variables = {
      RDS_ENDPOINT = aws_db_instance.MyRDSInstance.endpoint
      RDS_USERNAME = var.db_username
      RDS_PASSWORD = var.db_password
    }
  }