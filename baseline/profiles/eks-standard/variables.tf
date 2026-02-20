# AWS Security Group Platform - EKS Standard Profile Variables

variable "vpc_id" {
  description = "VPC ID where security groups will be created"
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

variable "eks_cluster_name" {
  description = "Name of the EKS cluster (optional, used for tagging)"
  type        = string
  default     = ""
}