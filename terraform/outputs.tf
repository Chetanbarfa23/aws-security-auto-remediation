output "demo_security_group_id" {
  description = "ID of the intentionally insecure demo security group"
  value       = aws_security_group.demo_insecure.id
}