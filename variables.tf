variable "aws_vpc_cidr" {
  description = "The CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}
variable "db_username" {
  description = "The username for the RDS database"
  type        = string 
}
variable "db_password" {
  type      = string
  sensitive = true
}