variable "organisation_id" {
  description = "AWS Organizations id every principal in this account belongs to."
  type        = string

  validation {
    condition     = can(regex("^o-[a-z0-9]{10,32}$", var.organisation_id))
    error_message = "organisation_id must be an o- identifier."
  }
}

variable "public_subnet_ids" {
  description = "Public subnets the edge load balancer sits in."
  type        = list(string)
}

variable "reporting_db_secret_arn" {
  description = <<-EOT
    ARN of the Secrets Manager secret holding the reporting warehouse
    credentials. The secret is created and rotated outside this stack by the
    platform rotation Lambda; Terraform only reads the current version.
  EOT
  type        = string
}

locals {
  edge_name = "slopshop-${var.environment}-edge"
}

# ---------------------------------------------------------------------------
# Network ACL
# ---------------------------------------------------------------------------

resource "aws_network_acl" "edge" {
  vpc_id     = var.vpc_id
  subnet_ids = var.public_subnet_ids

  tags = {
    Name = local.edge_name
  }
}

# Ephemeral return traffic for connections the edge itself opened.
resource "aws_network_acl_rule" "edge_ingress_ephemeral" {
  network_acl_id = aws_network_acl.edge.id
  rule_number    = 100
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "10.0.0.0/8"
  from_port      = 1024
  to_port        = 65535
}

# HTTPS from the CDN's published ranges, which the caller passes in.
resource "aws_network_acl_rule" "edge_ingress_https" {
  for_each = { for index, cidr in var.ingress_cidr_blocks : index => cidr }

  network_acl_id = aws_network_acl.edge.id
  rule_number    = 200 + tonumber(each.key)
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = each.value
  from_port      = 443
  to_port        = 443
}

# Explicit catch-all, numbered above the allow rules.
resource "aws_network_acl_rule" "edge_ingress_deny_remainder" {
  network_acl_id = aws_network_acl.edge.id
  rule_number    = 900
  egress         = false
  protocol       = "-1"
  rule_action    = "deny"
  cidr_block     = "0.0.0.0/0"
  from_port      = 0
  to_port        = 0
}

resource "aws_network_acl_rule" "edge_egress_deny_remainder" {
  network_acl_id = aws_network_acl.edge.id
  rule_number    = 900
  egress         = true
  protocol       = "-1"
  rule_action    = "deny"
  cidr_block     = "0.0.0.0/0"
  from_port      = 0
  to_port        = 0
}

resource "aws_network_acl_rule" "edge_egress_to_application" {
  network_acl_id = aws_network_acl.edge.id
  rule_number    = 100
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "10.0.0.0/8"
  from_port      = 8080
  to_port        = 8080
}

# ---------------------------------------------------------------------------
# Instance discovery role
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "discovery_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

# The edge nodes call a handful of describe operations at boot to work out
# their own placement.
data "aws_iam_policy_document" "discovery" {
  statement {
    sid    = "AccountLevelDescribes"
    effect = "Allow"

    actions = [
      "ec2:DescribeRegions",
      "ec2:DescribeAvailabilityZones",
      "sts:GetCallerIdentity",
      "cloudwatch:ListMetrics",
      "tag:GetResources",
    ]

    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"
      values   = [var.organisation_id]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = [var.region]
    }
  }
}

resource "aws_iam_role" "discovery" {
  name               = "${local.edge_name}-discovery"
  assume_role_policy = data.aws_iam_policy_document.discovery_trust.json
}

resource "aws_iam_policy" "discovery" {
  name   = "${local.edge_name}-discovery"
  policy = data.aws_iam_policy_document.discovery.json
}

resource "aws_iam_role_policy_attachment" "discovery" {
  role       = aws_iam_role.discovery.name
  policy_arn = aws_iam_policy.discovery.arn
}

# ---------------------------------------------------------------------------
# Reporting warehouse
# ---------------------------------------------------------------------------

data "aws_secretsmanager_secret" "reporting_db" {
  arn = var.reporting_db_secret_arn
}

data "aws_secretsmanager_secret_version" "reporting_db" {
  secret_id = data.aws_secretsmanager_secret.reporting_db.id
}

locals {
  reporting_credentials = jsondecode(
    data.aws_secretsmanager_secret_version.reporting_db.secret_string
  )
}

resource "aws_rds_cluster" "reporting" {
  cluster_identifier = "slopshop-${var.environment}-reporting"
  engine             = "aurora-postgresql"
  engine_mode        = "provisioned"
  engine_version     = "16.4"

  database_name   = "reporting"
  master_username = local.reporting_credentials["username"]
  master_password = local.reporting_credentials["password"]

  db_subnet_group_name   = aws_db_subnet_group.primary.name
  vpc_security_group_ids = [aws_security_group.database.id]

  storage_encrypted   = true
  kms_key_id          = aws_kms_key.platform.arn
  deletion_protection = true

  backup_retention_period      = var.backup_retention_days
  preferred_backup_window      = "02:00-03:00"
  preferred_maintenance_window = "sun:04:30-sun:05:30"
  copy_tags_to_snapshot        = true
  skip_final_snapshot          = false
  final_snapshot_identifier    = "slopshop-${var.environment}-reporting-final"

  iam_database_authentication_enabled = true
  enabled_cloudwatch_logs_exports     = ["postgresql"]

  serverlessv2_scaling_configuration {
    min_capacity = 0.5
    max_capacity = 8
  }

  lifecycle {
    # The rotation Lambda owns the credentials after creation.
    ignore_changes = [master_username, master_password]
  }
}

resource "aws_rds_cluster_instance" "reporting" {
  count = 2

  identifier          = "slopshop-${var.environment}-reporting-${count.index}"
  cluster_identifier  = aws_rds_cluster.reporting.id
  instance_class      = "db.serverless"
  engine              = aws_rds_cluster.reporting.engine
  engine_version      = aws_rds_cluster.reporting.engine_version
  publicly_accessible = false

  performance_insights_enabled    = true
  performance_insights_kms_key_id = aws_kms_key.platform.arn
}

output "reporting_endpoint" {
  description = "Writer endpoint of the reporting warehouse."
  value       = aws_rds_cluster.reporting.endpoint
}
