# AWS Security Group Platform - Internet Ingress Profile Variables

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

variable "waf_custom_ports" {
  description = "Custom ports for WAF/CDN to NLB traffic beyond standard 80/443"
  type        = list(number)
  default     = [8080, 8443, 9000]
  
  validation {
    condition = alltrue([
      for port in var.waf_custom_ports : port > 0 && port <= 65535
    ])
    error_message = "All ports must be between 1 and 65535."
  }
}