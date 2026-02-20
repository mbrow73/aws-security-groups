# AWS Security Group Platform - VPC Endpoints Profile Variables

variable "vpc_id" {
  description = "VPC ID where security groups will be created"
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR block for internal access rules"
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

variable "additional_vpc_endpoint_ports" {
  description = "Additional ports for VPC endpoint access beyond the standard 80/443"
  type = list(object({
    port    = number
    service = string
  }))
  default = [
    {
      port    = 8080
      service = "custom-api"
    }
  ]
}