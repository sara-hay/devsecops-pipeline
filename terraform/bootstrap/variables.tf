variable "region" {
  description = "AWS region for the state bucket (matches the region the pipeline already uses)."
  type        = string
  default     = "us-east-1"
}
