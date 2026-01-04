terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.22.1"
    }
  }
}
provider "aws" {
  # Configuration options
  region  = "us-west-2"
  profile = "my-admin-profile"
}
# Add on for WAF Configuration  
provider "aws" {
  alias  = "use1"
  region = "us-east-1"
}