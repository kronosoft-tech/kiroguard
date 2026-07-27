variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "kiroguard"
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR block for public subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "freedns_domain" {
  description = "FreeDNS domain name pointing to the Elastic IP (e.g., kiroguard.mooo.com)"
  type        = string
  default     = "kiroguard.mooo.com"
}

variable "container_image" {
  description = "Container image URI (ECR or Docker Hub)"
  type        = string
  default     = "kronosoft/kiroguard:latest"
}

variable "deploy_branch" {
  description = "Git branch to build the KiroGuard container from on the EC2 instance"
  type        = string
  default     = "develop"
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.small"
}

variable "allowed_ssh_cidr" {
  description = "CIDR allowed for SSH access"
  type        = string
  default     = "0.0.0.0/0"
}

variable "key_name" {
  description = "AWS EC2 Key Pair name for SSH access (optional)"
  type        = string
  default     = ""
}

variable "bedrock_model_arns" {
  description = "List of Bedrock model ARNs KiroGuard can invoke"
  type        = list(string)
  default     = ["arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-v3-sonnet"]
}

variable "alert_email" {
  description = "Email address to receive DevSecOps security alerts via SNS"
  type        = string
  default     = "secops@example.com"
}
