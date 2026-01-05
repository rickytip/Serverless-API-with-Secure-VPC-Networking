# **Serverless API Gateway Lambda RDS Project Using Terraform**

## **Overview**
This project demonstrates how to build a complete serverless application on AWS using infrastructure as code. The application accepts requests through API Gateway, processes them with a Lambda function in private subnets, and stores or retrieves data from an Amazon RDS MySQL database. AWS Secrets Manager and AWS KMS are used to protect sensitive credentials, while all infrastructure is deployed and managed through Terraform.

This project is designed to show cloud security practices including network isolation, least privilege design, encrypted secrets, and strong access controls.

<img width="695" height="296" alt="Screenshot 2025-12-02 at 10 49 13 AM" src="https://github.com/user-attachments/assets/2b62409f-2a7a-416c-839e-ccc5438fa440" />



## **Architecture summary**

The architecture contains the following components

- A public API Gateway that accepts user requests
- A Lambda function that runs inside private subnets in a VPC
- An RDS MySQL instance deployed in isolated database subnets
- Secrets Manager which stores the database password and returns it securely to the Lambda function
- A KMS key that encrypts the secret
- One VPC with public subnets and private subnets across multiple Availability Zones
- A NAT gateway that allows private subnets to reach AWS service endpoints
- An internet gateway for public connectivity
- Security groups that restrict traffic so only the Lambda security group can reach the RDS instance

## **Request flow**

1. A user sends a request to API Gateway

2. API Gateway triggers the Lambda function through an IAM permission

3. The Lambda function retrieves the database password from Secrets Manager

4. Secrets Manager decrypts the value using the KMS key

5. Lambda connects to the RDS instance inside the private database subnets

6. The response is returned to the user through API Gateway

## **Security design**

This project demonstrates several important cloud security practices

- Lambda and RDS are deployed in private subnets with no public exposure
- The RDS security group only allows inbound traffic from the Lambda security group
- Secrets Manager and KMS protect database credentials
- IAM roles ensure each component can only perform the required actions
- Network routes restrict how traffic enters and exits the environment
- Terraform builds the entire system consistently and repeatably


## **Documentation**

📄 Full Architecture & Implementation Guide [Secure Serverless API on AWS.pdf](https://github.com/user-attachments/files/24425872/Secure.Serverless.API.on.AWS.pdf)

This project includes a 32-page PDF with:

Architecture diagrams

Terraform explanations

Phase-by-phase breakdowns

Security design rationale

Troubleshooting notes and fixes

Screenshots from testing and validation
