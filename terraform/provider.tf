terraform {
  required_version = ">= 1.5.0"

  required_providers {

    // aws provider
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    // TLS = Transport Layer Security
    // TLS keeps data private and secure while it travels over the internet.

    // tls provider
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = "ap-south-1"
}


// GitHub ko AWS mein securely login karwana without permanent access keys.