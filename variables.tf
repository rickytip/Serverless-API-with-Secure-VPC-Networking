variable "aws_vpc_cidr" {
  description = "The CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}
variable "DB_NAME" {
  description = "Name of the database schema"
  type        = string
}
variable "DB_PASSWORD" {
  description = "Master password for the RDS instance"
  type        = string
  sensitive   = true
}
variable "DB_PORT" {
  description = "Port the database listens on"
  type        = string
  default     = "3306"
}
variable "DB_HOST" {
  description = "Hostname of the RDS instance"
  type        = string
}
variable "DB_USER" {
  description = "Database user for application access"
  type        = string
}
variable "aws_region" {
  description = "The AWS region to deploy resources in"
  type        = string
  default     = "us-west-2" 
}