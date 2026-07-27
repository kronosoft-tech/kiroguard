output "elastic_ip" {
  description = "Static Elastic IP allocated for KiroGuard — point your FreeDNS A Record here"
  value       = aws_eip.kiroguard.public_ip
}

output "freedns_domain" {
  description = "FreeDNS Domain Name"
  value       = var.freedns_domain
}

output "https_mcp_url" {
  description = "HTTPS URL for KiroGuard MCP Server (for IDE connection)"
  value       = "https://${var.freedns_domain}"
}

output "ssh_command" {
  description = "Command to SSH into the KiroGuard EC2 instance"
  value       = "ssh ec2-user@${aws_eip.kiroguard.public_ip}"
}

output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}
