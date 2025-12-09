data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

locals {
  region                 = var.region == null ? data.aws_region.current.region : var.region
  bucket_arn_placeholder = "{BUCKET_ARN}"
}
