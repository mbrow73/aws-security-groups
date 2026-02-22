output "security_group_ids" {
  description = "Map of SG names to their IDs"
  value = {
    for sg_name, sg in module.security_groups :
    sg_name => sg.security_group_id
  }
}

output "account_id" {
  description = "Account ID from YAML"
  value       = local.account_id
}
