# EKS Internet Profile Outputs

output "eks_cluster_security_group_id" {
  description = "ID of the EKS cluster control plane security group"
  value       = aws_security_group.eks_cluster.id
}

output "eks_workers_security_group_id" {
  description = "ID of the EKS worker nodes security group"
  value       = aws_security_group.eks_workers.id
}

output "istio_intranet_nodes_security_group_id" {
  description = "ID of the intranet istio gateway nodes security group"
  value       = aws_security_group.istio_intranet_nodes.id
}

output "intranet_nlb_security_group_id" {
  description = "ID of the intranet NLB security group"
  value       = aws_security_group.intranet_nlb.id
}

output "istio_inet_nodes_security_group_id" {
  description = "ID of the internet istio gateway nodes security group"
  value       = aws_security_group.istio_inet_nodes.id
}

output "internet_nlb_security_group_id" {
  description = "ID of the internet NLB security group"
  value       = aws_security_group.internet_nlb.id
}
