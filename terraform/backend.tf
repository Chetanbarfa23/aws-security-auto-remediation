# ============================================================
# Terraform Remote Backend
# ============================================================

terraform {
  backend "s3" {
    # S3 stores the shared Terraform state
    bucket = "aws-security-auto-remediation-terraform-state-438546837574"

    # State file location inside S3
    key = "security-auto-remediation/terraform.tfstate"

    # AWS region
    region = "ap-south-1"

    # Use S3 native state locking
    use_lockfile = true

    # Encrypt Terraform state
    encrypt = true
  }
}