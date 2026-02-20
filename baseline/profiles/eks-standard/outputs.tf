# AWS Security Group Platform - EKS Standard Profile Outputs

output "eks_cluster_security_group_id" {
  description = "ID of the EKS cluster baseline security group"
  value       = aws_security_group.eks_cluster_baseline.id
}

output "eks_cluster_security_group_arn" {
  description = "ARN of the EKS cluster baseline security group"
  value       = aws_security_group.eks_cluster_baseline.arn
}

output "eks_cluster_security_group_name" {
  description = "Name of the EKS cluster baseline security group"
  value       = aws_security_group.eks_cluster_baseline.name
}