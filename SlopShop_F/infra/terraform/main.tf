terraform {
  required_version = "~> 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.82"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  backend "s3" {
    bucket       = "slopshop-terraform-state"
    key          = "platform/terraform.tfstate"
    region       = "eu-west-2"
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = merge(var.tags, {
      Environment = var.environment
      Service     = "slopshop"
      ManagedBy   = "terraform"
    })
  }
}

locals {
  name_prefix = "slopshop-${var.environment}"
}

# ---------------------------------------------------------------------------
# Encryption key
# ---------------------------------------------------------------------------

data "aws_caller_identity" "current" {}

resource "aws_kms_key" "platform" {
  description             = "Customer managed key for ${local.name_prefix} data at rest"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 30
  multi_region            = false

  # Without an explicit policy the key falls back to the account default, which
  # grants use to every principal IAM allows. This one names the key
  # administrators and the four services that may encrypt with it, and confines
  # service use to this account.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "KeyAdministration"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "PlatformServiceUse"
        Effect = "Allow"
        Principal = {
          Service = [
            "s3.amazonaws.com",
            "rds.amazonaws.com",
            "logs.${var.region}.amazonaws.com",
            "secretsmanager.amazonaws.com",
          ]
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
    ]
  })
}

resource "aws_kms_alias" "platform" {
  name          = "alias/${local.name_prefix}"
  target_key_id = aws_kms_key.platform.key_id
}

# ---------------------------------------------------------------------------
# Artifact storage
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "artifacts" {
  bucket = "${local.name_prefix}-artifacts"
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.platform.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_logging" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "artifacts/"
}

resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    id     = "expire-noncurrent"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 90
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# Transport and encryption requirements for the bucket.
data "aws_iam_policy_document" "artifacts" {
  statement {
    sid    = "DenyPlaintextTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.artifacts.arn,
      "${aws_s3_bucket.artifacts.arn}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid    = "DenyUnencryptedUploads"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.artifacts.arn}/*"]

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }
}

resource "aws_s3_bucket_policy" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  policy = data.aws_iam_policy_document.artifacts.json

  depends_on = [aws_s3_bucket_public_access_block.artifacts]
}

resource "aws_s3_bucket" "access_logs" {
  bucket = "${local.name_prefix}-access-logs"
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.platform.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    id     = "expire-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = 400
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

resource "aws_security_group" "load_balancer" {
  name        = "${local.name_prefix}-lb"
  description = "Ingress to the public load balancer"
  vpc_id      = var.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "load_balancer_https" {
  for_each = toset(var.ingress_cidr_blocks)

  security_group_id = aws_security_group.load_balancer.id
  description       = "HTTPS from an approved edge range"
  cidr_ipv4         = each.value
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "load_balancer_to_app" {
  security_group_id            = aws_security_group.load_balancer.id
  description                  = "Forward to the application tier"
  referenced_security_group_id = aws_security_group.application.id
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
}

resource "aws_security_group" "application" {
  name        = "${local.name_prefix}-app"
  description = "Application tier"
  vpc_id      = var.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "application_from_lb" {
  security_group_id            = aws_security_group.application.id
  description                  = "Traffic from the load balancer only"
  referenced_security_group_id = aws_security_group.load_balancer.id
  from_port                    = 8080
  to_port                      = 8080
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "application_to_database" {
  security_group_id            = aws_security_group.application.id
  description                  = "PostgreSQL to the primary database"
  referenced_security_group_id = aws_security_group.database.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

# Outbound HTTPS goes to the managed prefix lists for the AWS service endpoints
# the application uses.
data "aws_ec2_managed_prefix_list" "s3" {
  name = "com.amazonaws.${var.region}.s3"
}

data "aws_ec2_managed_prefix_list" "dynamodb" {
  name = "com.amazonaws.${var.region}.dynamodb"
}

resource "aws_vpc_security_group_egress_rule" "application_to_s3" {
  security_group_id = aws_security_group.application.id
  description       = "HTTPS to the S3 gateway endpoint"
  prefix_list_id    = data.aws_ec2_managed_prefix_list.s3.id
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "application_to_dynamodb" {
  security_group_id = aws_security_group.application.id
  description       = "HTTPS to the DynamoDB gateway endpoint"
  prefix_list_id    = data.aws_ec2_managed_prefix_list.dynamodb.id
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_security_group" "database" {
  name        = "${local.name_prefix}-db"
  description = "Primary database"
  vpc_id      = var.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "database_from_application" {
  security_group_id            = aws_security_group.database.id
  description                  = "PostgreSQL from the application tier only"
  referenced_security_group_id = aws_security_group.application.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

resource "aws_db_subnet_group" "primary" {
  name       = "${local.name_prefix}-primary"
  subnet_ids = var.private_subnet_ids
}

resource "aws_db_parameter_group" "primary" {
  name   = "${local.name_prefix}-pg16"
  family = "postgres16"

  # Refuse any connection that is not encrypted in transit.
  parameter {
    name         = "rds.force_ssl"
    value        = "1"
    apply_method = "pending-reboot"
  }

  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_disconnections"
    value = "1"
  }
}

resource "aws_db_instance" "primary" {
  identifier     = "${local.name_prefix}-primary"
  engine         = "postgres"
  engine_version = "16.6"
  instance_class = var.database_instance_class

  allocated_storage     = 200
  max_allocated_storage = 1000
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.platform.arn

  db_name  = "slopshop"
  username = "slopshop_migrator"

  # The password is generated by RDS and stored in Secrets Manager under the
  # platform key.
  manage_master_user_password   = true
  master_user_secret_kms_key_id = aws_kms_key.platform.arn

  db_subnet_group_name   = aws_db_subnet_group.primary.name
  parameter_group_name   = aws_db_parameter_group.primary.name
  vpc_security_group_ids = [aws_security_group.database.id]
  publicly_accessible    = false
  multi_az               = true

  backup_retention_period   = var.backup_retention_days
  backup_window             = "02:00-03:00"
  maintenance_window        = "sun:03:30-sun:04:30"
  copy_tags_to_snapshot     = true
  deletion_protection       = true
  skip_final_snapshot       = false
  final_snapshot_identifier = "${local.name_prefix}-final"

  auto_minor_version_upgrade          = true
  iam_database_authentication_enabled = true

  performance_insights_enabled          = true
  performance_insights_kms_key_id       = aws_kms_key.platform.arn
  performance_insights_retention_period = 93

  monitoring_interval = 30
  monitoring_role_arn = aws_iam_role.rds_monitoring.arn

  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
}

data "aws_iam_policy_document" "rds_monitoring_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["monitoring.rds.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "rds_monitoring" {
  name               = "${local.name_prefix}-rds-monitoring"
  assume_role_policy = data.aws_iam_policy_document.rds_monitoring_trust.json
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "application" {
  name              = "/slopshop/${var.environment}/application"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.platform.arn
}

output "database_endpoint" {
  description = "Endpoint of the primary database."
  value       = aws_db_instance.primary.endpoint
}

output "artifact_bucket" {
  description = "Bucket rendered artifacts are stored in."
  value       = aws_s3_bucket.artifacts.bucket
}
