output "alb_dns_name" {
  description = "DNS name of the ALB — point your CNAME here"
  value       = aws_lb.kiroguard.dns_name
}

output "ecs_cluster_name" {
  description = "Name of the ECS cluster"
  value       = aws_ecs_cluster.kiroguard.name
}

output "ecs_service_name" {
  description = "Name of the ECS service"
  value       = aws_ecs_service.kiroguard.name
}

output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "task_role_arn" {
  description = "ARN of the KiroGuard task IAM role"
  value       = aws_iam_role.kiroguard_task.arn
}
