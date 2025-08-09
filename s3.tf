resource "aws_s3_bucket" "this" {
  bucket              = "${var.name}${var.append_region_suffix ? "-${data.aws_region.current.region}" : ""}"
  object_lock_enabled = var.object_lock_enabled
  force_destroy       = var.force_destroy
  tags                = var.tags_s3_bucket
}

resource "terraform_data" "mfa_delete_serial_number" {
  input = var.mfa_delete_serial_number
}

module "assert_mfa_delete_parameters" {
  source        = "Invicton-Labs/assertion/null"
  version       = "~>0.2.7"
  condition     = var.mfa_delete_enabled ? (var.mfa_delete_serial_number != null && var.mfa_delete_token_code != null) : true
  error_message = "If the `mfa_delete_enabled` variable is `true`, both the `mfa_delete_serial_number` and `mfa_delete_token_code` variables must be provided."
}

resource "aws_s3_bucket_versioning" "this" {
  depends_on = [
    module.assert_mfa_delete_parameters
  ]
  bucket                = aws_s3_bucket.this.id
  expected_bucket_owner = data.aws_caller_identity.current.account_id
  versioning_configuration {
    status     = var.versioned ? "Enabled" : "Suspended"
    mfa_delete = var.mfa_delete_enabled ? "Enabled" : "Disabled"
  }
  mfa = var.mfa_delete_enabled ? "${var.mfa_delete_serial_number} ${var.mfa_delete_token_code}" : null
  lifecycle {
    ignore_changes = [
      // We ignore MFA as a field because it includes the 
      // MFA token code, which rotates regularly.
      mfa,
    ]
    replace_triggered_by = [
      // Since we're ignoring the MFA field, we explicitly trigger
      // a replace if the MFA delete device serial number changes.
      terraform_data.mfa_delete_serial_number
    ]
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  depends_on = [
    aws_s3_bucket_versioning.this
  ]
  bucket                = aws_s3_bucket.this.id
  expected_bucket_owner = data.aws_caller_identity.current.account_id
  rule {
    bucket_key_enabled = local.used_kms_key_arn == null ? null : true
    apply_server_side_encryption_by_default {
      sse_algorithm     = local.used_kms_key_arn == null ? "AES256" : "aws:kms"
      kms_master_key_id = local.used_kms_key_arn == null ? null : local.used_kms_key_arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  depends_on = [
    aws_s3_bucket_server_side_encryption_configuration.this
  ]
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = var.block_public_acls
  block_public_policy     = var.block_public_policy
  ignore_public_acls      = var.ignore_public_acls
  restrict_public_buckets = var.restrict_public_buckets
}

resource "aws_s3_bucket_ownership_controls" "this" {
  depends_on = [
    aws_s3_bucket_public_access_block.this
  ]
  bucket = aws_s3_bucket.this.id
  rule {
    object_ownership = var.object_ownership
  }
}

locals {
  // We have to do special things to allow CloudTrail digests to be written, since they
  // refuse to use KMS keys.
  // https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html
  allow_cloudtrail_digest = var.force_allow_cloudtrail_digest && local.used_kms_key_arn != null
}

// Create a bucket policy that requires all uploaded objects to be encrypted
data "aws_iam_policy_document" "this" {

  // Also apply all of the input policies, but don't let them override the security/encryption ones
  // Replace the BUCKET_ARN placeholder.
  source_policy_documents = [
    for policy in var.bucket_policy_json_documents :
    replace(policy, local.bucket_arn_placeholder, aws_s3_bucket.this.arn)
  ]

  // This statement grants all permissions to the owner account. While not strictly necessary,
  // it also serves to ensure that the policy is never empty, which would throw errors.
  statement {
    actions = [
      "s3:*"
    ]
    resources = [
      aws_s3_bucket.this.arn,
      "${aws_s3_bucket.this.arn}/*"
    ]
    principals {
      type = "AWS"
      identifiers = [
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      ]
    }
  }

  // If an encryption header is provided, ensure it matches the default
  statement {
    sid    = "DenyIncorrectEncryptionHeader"
    effect = "Deny"

    // It's uploading objects that we want to prevent (if the request doesn't meet the conditions)
    actions = [
      "s3:PutObject",
    ]

    // Apply this statement to ALL resources in the bucket
    resources = [
      "${aws_s3_bucket.this.arn}/*",
    ]

    // The statement applies to EVERYTHING
    principals {
      type = "*"
      identifiers = [
        "*"
      ]
    }

    // If we're doing special CloudTrail rules, add an exemption for CloudTrail
    dynamic "condition" {
      for_each = local.allow_cloudtrail_digest ? [1] : []
      content {
        variable = "aws:PrincipalServiceName"
        test     = "StringNotEqualsIfExists"
        values = [
          "cloudtrail.amazonaws.com"
        ]
      }
    }

    // Trigger this deny if the header is provided AND
    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption"
      values = [
        false
      ]
    }
    // Its value doesn't match the expected one
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values = [
        local.used_kms_key_arn == null ? "AES256" : "aws:kms",
      ]
    }
  }

  dynamic "statement" {
    for_each = local.allow_cloudtrail_digest ? [1] : []
    content {
      sid    = "DenyUnencryptedCloudTrail"
      effect = "Deny"

      // This applies to everything, INCLUDING CloudTrail
      principals {
        type = "*"
        identifiers = [
          "*"
        ]
      }

      // It's uploading objects that we want to prevent (if the request doesn't meet the conditions)
      actions = [
        "s3:PutObject",
      ]

      // Apply this statement to ALL resources in the bucket OTHER than those written by CloudTrail digests
      not_resources = [
        // This ARN represents the paths that CloudTrail Digest logs could be written to
        // https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-digest-file-structure.html#cloudtrail-log-file-validation-digest-file-location
        "${aws_s3_bucket.this.arn}/*/AWSLogs/*/CloudTrail-Digest/*",
        "${aws_s3_bucket.this.arn}/AWSLogs/*/CloudTrail-Digest/*"
      ]

      // Trigger this deny if the encryption header is provided (NOT NULL) AND
      condition {
        test     = "Null"
        variable = "s3:x-amz-server-side-encryption"
        values = [
          false
        ]
      }
      // It's not using the right type of encryption
      condition {
        test     = "StringNotEquals"
        variable = "s3:x-amz-server-side-encryption"
        values = [
          local.used_kms_key_arn == null ? "AES256" : "aws:kms",
        ]
      }
    }
  }

  // If we're using KMS, then ensure that if a KMS key is provided, it matches the default
  dynamic "statement" {
    for_each = local.used_kms_key_arn == null ? [] : [local.used_kms_key_arn]
    content {
      sid    = "DenyIncorrectKmsKeyId"
      effect = "Deny"
      principals {
        type = "*"
        identifiers = [
          "*"
        ]
      }
      actions = [
        "s3:PutObject",
      ]
      resources = [
        "${aws_s3_bucket.this.arn}/*",
      ]
      // Trigger this deny if the header is provided (NOT NULL) AND
      condition {
        test     = "Null"
        variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
        values = [
          false
        ]
      }
      // Its value doesn't match the expected one
      condition {
        test     = "StringNotEquals"
        variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
        values = [
          statement.value
        ]
      }
    }
  }

  dynamic "statement" {
    for_each = var.enable_shield_drt_access ? [null] : []
    content {
      sid    = "AWSDDoSResponseTeamAccessS3Bucket"
      effect = "Allow"
      principals {
        type = "Service"
        identifiers = [
          "drt.shield.amazonaws.com"
        ]
      }
      actions = [
        "s3:GetBucketLocation",
        "s3:GetObject",
        "s3:ListBucket",
      ]
      resources = [
        aws_s3_bucket.this.arn,
        "${aws_s3_bucket.this.arn}/*"
      ]
    }
  }
}

// Set the policy on the bucket
resource "aws_s3_bucket_policy" "this" {
  depends_on = [
    aws_s3_bucket_ownership_controls.this
  ]
  bucket = aws_s3_bucket.this.id
  policy = data.aws_iam_policy_document.this.json
}

resource "aws_s3_bucket_cors_configuration" "this" {
  count                 = length(var.cors_rules) > 0 ? 1 : 0
  depends_on            = [aws_s3_bucket_policy.this]
  bucket                = aws_s3_bucket.this.id
  expected_bucket_owner = data.aws_caller_identity.current.account_id
  dynamic "cors_rule" {
    for_each = var.cors_rules
    content {
      allowed_headers = cors_rule.value.allowed_headers
      allowed_methods = cors_rule.value.allowed_methods
      allowed_origins = cors_rule.value.allowed_origins
      expose_headers  = cors_rule.value.expose_headers
      id              = cors_rule.value.id
      max_age_seconds = cors_rule.value.max_age_seconds
    }
  }
}

// Enable acceleration if desired. We do it this way (only create the resource
// if acceleration is enabled) because some regions don't support transfer
// acceleration, even if we try to set it to "Suspended".
resource "aws_s3_bucket_accelerate_configuration" "this" {
  count = var.enable_transfer_acceleration ? 1 : 0
  depends_on = [
    aws_s3_bucket_cors_configuration.this
  ]
  expected_bucket_owner = data.aws_caller_identity.current.account_id
  bucket                = aws_s3_bucket.this.id
  status                = "Enabled"
}
