variable "environment" {
  description = "Deployment environment this stack represents."
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of dev, staging or prod."
  }
}

variable "region" {
  description = "Region the stack is deployed into."
  type        = string
  default     = "eu-west-2"

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-[0-9]$", var.region))
    error_message = "region must look like eu-west-2."
  }
}

variable "vpc_id" {
  description = "VPC the workloads run in."
  type        = string

  validation {
    condition     = can(regex("^vpc-[0-9a-f]{8,17}$", var.vpc_id))
    error_message = "vpc_id must be a vpc- identifier."
  }
}

variable "private_subnet_ids" {
  description = "Private subnets for the database and the application nodes."
  type        = list(string)

  validation {
    condition     = length(var.private_subnet_ids) >= 2
    error_message = "at least two private subnets are required for a multi-AZ deployment."
  }
}

variable "ingress_cidr_blocks" {
  description = <<-EOT
    CIDR ranges permitted to reach the load balancer. Public traffic arrives
    through the CDN, whose published ranges are supplied here.
  EOT
  type        = list(string)

  validation {
    condition = alltrue([
      for cidr in var.ingress_cidr_blocks :
      can(cidrnetmask(cidr)) && tonumber(split("/", cidr)[1]) >= 16
    ])
    error_message = "each ingress CIDR must be valid and no wider than a /16."
  }

  validation {
    condition     = !contains(var.ingress_cidr_blocks, "0.0.0.0/0")
    error_message = "the load balancer must not be opened to every address."
  }
}

variable "database_instance_class" {
  description = "Instance class for the primary database."
  type        = string
  default     = "db.m6g.large"
}

variable "backup_retention_days" {
  description = "How long automated database backups are kept."
  type        = number
  default     = 30

  validation {
    condition     = var.backup_retention_days >= 7 && var.backup_retention_days <= 35
    error_message = "backup retention must be between 7 and 35 days."
  }
}

variable "log_retention_days" {
  description = "How long application logs are retained."
  type        = number
  default     = 365
}

variable "tags" {
  description = "Tags applied to every resource in the stack."
  type        = map(string)
  default     = {}
}
