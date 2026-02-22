# VPC Endpoints Profile Variables

variable "vpc_id" {
  description = "VPC ID where the security group will be created"
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR block for ingress rules"
  type        = string
}

variable "account_id" {
  description = "AWS Account ID"
  type        = string
}

variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default     = {}
}
