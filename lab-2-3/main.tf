terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# Bucket principal de evidencia
resource "aws_s3_bucket" "evidence_vault" {
  bucket = "grc-lab-evidence-carlos-2026"

  tags = {
    Project     = "terraform-labs"
    Environment = "dev"
    Lab         = "2.3"
    Owner       = "carlos-molina"
  }
}

# SC-28: Proteccion de datos en reposo
resource "aws_s3_bucket_server_side_encryption_configuration" "vault_encryption" {
  bucket = aws_s3_bucket.evidence_vault.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

# AC-3: Bloqueo de acceso publico
resource "aws_s3_bucket_public_access_block" "vault_public_block" {
  bucket = aws_s3_bucket.evidence_vault.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# CM-6: Versionamiento obligatorio
resource "aws_s3_bucket_versioning" "vault_versioning" {
  bucket = aws_s3_bucket.evidence_vault.id

  versioning_configuration {
    status = "Enabled"
  }
}

# AU-3 / AU-6: Logging de acceso
resource "aws_s3_bucket_logging" "vault_logging" {
  bucket = aws_s3_bucket.evidence_vault.id

  target_bucket = aws_s3_bucket.evidence_vault.id
  target_prefix = "access-logs/"
}