// This generates a policy that allows the key's owner account to have full access via IAM
data "aws_iam_policy_document" "kms" {
  source_policy_documents = var.kms_key_policy_json_documents
  statement {
    sid    = "Enable IAM Access for Owner Account"
    effect = "Allow"
    actions = [
      "kms:*"
    ]
    resources = [
      "*"
    ]
    principals {
      type = "AWS"
      identifiers = [
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      ]
    }
  }
}

resource "aws_kms_key" "this" {
  count  = var.create_new_kms_key ? 1 : 0
  region = local.region
  depends_on = [
    module.assert_source_kms_key,
  ]
  description                        = "Encryption key for the S3 bucket \"${aws_s3_bucket.this.bucket}\""
  key_usage                          = "ENCRYPT_DECRYPT"
  customer_master_key_spec           = "SYMMETRIC_DEFAULT"
  bypass_policy_lockout_safety_check = false
  deletion_window_in_days            = 30
  is_enabled                         = true
  enable_key_rotation                = true
  multi_region                       = true
  policy                             = data.aws_iam_policy_document.kms.json
}

resource "aws_kms_replica_key" "this" {
  count  = var.create_replica_kms_key ? 1 : 0
  region = local.region
  depends_on = [
    module.assert_source_kms_key,
  ]
  description                        = "Encryption key for the S3 bucket \"${aws_s3_bucket.this.bucket}\""
  deletion_window_in_days            = 30
  primary_key_arn                    = var.kms_key_arn
  enabled                            = true
  bypass_policy_lockout_safety_check = false
  policy                             = data.aws_iam_policy_document.kms.json
}

locals {
  used_kms_key_arn = length(aws_kms_key.this) > 0 ? aws_kms_key.this[0].arn : length(aws_kms_replica_key.this) > 0 ? aws_kms_replica_key.this[0].arn : var.kms_key_arn
}

resource "aws_kms_alias" "this" {
  count         = length(aws_kms_key.this) > 0 || length(aws_kms_replica_key.this) > 0 ? 1 : 0
  region        = local.region
  name          = "alias/s3/${aws_s3_bucket.this.bucket}"
  target_key_id = local.used_kms_key_arn
}
