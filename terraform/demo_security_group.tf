# ============================================================
# Demo Insecure Security Group
# ============================================================

# Get the default VPC
data "aws_vpc" "default" {
  default = true
}

# Create a demo security group
resource "aws_security_group" "demo_insecure" {
  name        = "demo-insecure-security-group"
  description = "Demo security group with intentionally open SSH"
  vpc_id      = data.aws_vpc.default.id

  # INTENTIONALLY INSECURE
  # SSH is open to the entire internet.
  ingress {
    description = "Demo open SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"

    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow outbound traffic
  egress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"

    cidr_blocks = ["0.0.0.0/0"]
  }
}