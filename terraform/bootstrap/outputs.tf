output "state_bucket_name" {
  description = "Name of the S3 bucket to use in the main configuration's backend block."
  value       = aws_s3_bucket.state.id
}
