# AWS Security Group Platform - VPC Endpoints Profile Outputs

output "vpc_endpoints_security_group_id" {
  description = "ID of the VPC endpoints security group"
  value       = aws_security_group.vpc_endpoints.id
}

output "vpc_endpoints_security_group_arn" {
  description = "ARN of the VPC endpoints security group"
  value       = aws_security_group.vpc_endpoints.arn
}

output "vpc_endpoints_security_group_name" {
  description = "Name of the VPC endpoints security group"
  value       = aws_security_group.vpc_endpoints.name
}