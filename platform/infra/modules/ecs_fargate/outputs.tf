output "cluster_name" {
  value = aws_ecs_cluster.main.name
}

output "pentest_worker_service_name" {
  value = aws_ecs_service.pentest_worker.name
}

output "test_target_dns" {
  description = "Internal DNS for test-target: test-target.securityplatform.local"
  value       = var.enable_demo_target ? "test-target.${aws_service_discovery_private_dns_namespace.main[0].name}" : ""
}

output "pentest_worker_ecr_url" {
  value = aws_ecr_repository.pentest_worker.repository_url
}

output "test_target_ecr_url" {
  value = var.enable_demo_target ? aws_ecr_repository.test_target[0].repository_url : ""
}