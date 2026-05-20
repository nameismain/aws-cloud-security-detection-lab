output "vpc_id" {
  description = "Created VPC ID"
  value       = aws_vpc.main.id
}