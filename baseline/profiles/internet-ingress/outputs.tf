# AWS Security Group Platform - Internet Ingress Profile Outputs

output "waf_to_nlb_security_group_id" {
  description = "ID of the WAF to NLB security group"
  value       = aws_security_group.waf_to_nlb.id
}

output "waf_to_nlb_security_group_arn" {
  description = "ARN of the WAF to NLB security group"
  value       = aws_security_group.waf_to_nlb.arn
}

output "waf_to_nlb_security_group_name" {
  description = "Name of the WAF to NLB security group"
  value       = aws_security_group.waf_to_nlb.name
}