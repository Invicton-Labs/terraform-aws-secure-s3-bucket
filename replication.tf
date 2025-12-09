data "aws_iam_policy_document" "outbound_replication" {
  statement {
    sid    = "S3ReplicateFrom${join("", regexall("[0-9A-Za-z]+", aws_s3_bucket.this.id))}Bucket"
    effect = "Allow"
    actions = [
      "s3:GetReplicationConfiguration",
      "s3:ListBucket"
    ]
    resources = [
      aws_s3_bucket.this.arn
    ]
  }
  statement {
    sid    = "S3ReplicateFrom${join("", regexall("[0-9A-Za-z]+", aws_s3_bucket.this.id))}Objects"
    effect = "Allow"
    actions = [
      "s3:GetObjectVersionForReplication",
      "s3:GetObjectVersionAcl",
      "s3:GetObjectVersionTagging"
    ]
    resources = [
      "${aws_s3_bucket.this.arn}/*"
    ]
  }
  // If we're using a KMS key for decryption, the outbound replication needs
  // to be able to decrypt content that was encrypted using that key
  dynamic "statement" {
    for_each = local.used_kms_key_arn == null ? [] : [local.used_kms_key_arn]
    content {
      sid    = "S3KmsReplicateFrom${join("", regexall("[0-9A-Za-z]+", aws_s3_bucket.this.id))}"
      effect = "Allow"
      actions = [
        "kms:Decrypt"
      ]
      resources = [
        statement.value
      ]
      // Only allow decryption if it's being done via S3 in this region (source bucket region)
      condition {
        test     = "StringEquals"
        variable = "kms:ViaService"
        values = [
          "s3.${local.region}.amazonaws.com",
        ]
      }
      // Only allow decryption if the encryption context is valid
      condition {
        test     = "ArnLike"
        variable = "kms:EncryptionContext:aws:s3:arn"
        values = [
          // For bucket keys
          aws_s3_bucket.this.arn,
          // For specific object keys
          "${aws_s3_bucket.this.arn}/*"
        ]
      }
    }
  }
}

data "aws_iam_policy_document" "inbound_replication" {
  statement {
    sid    = "S3ReplicateTo${join("", regexall("[0-9A-Za-z]+", aws_s3_bucket.this.id))}"
    effect = "Allow"
    actions = [
      "s3:ReplicateObject",
      "s3:ReplicateDelete",
      "s3:ReplicateTags"
    ]
    resources = [
      "${aws_s3_bucket.this.arn}/*"
    ]
  }
  // If we're using a KMS key for decryption, the inbound replication needs
  // to be able to encrypt content using that key
  dynamic "statement" {
    for_each = local.used_kms_key_arn == null ? [] : [local.used_kms_key_arn]
    content {
      sid    = "S3KmsReplicateTo${join("", regexall("[0-9A-Za-z]+", aws_s3_bucket.this.id))}"
      effect = "Allow"
      actions = [
        "kms:Encrypt"
      ]
      resources = [
        statement.value
      ]
      // Only allow encryption if it's being done via S3 in this region (destination bucket region)
      condition {
        test     = "StringEquals"
        variable = "kms:ViaService"
        values = [
          "s3.${local.region}.amazonaws.com",
        ]
      }
      // Only allow decryption if the encryption context is valid
      condition {
        test     = "ArnLike"
        variable = "kms:EncryptionContext:aws:s3:arn"
        values = [
          // For bucket keys
          aws_s3_bucket.this.arn,
          // For specific object keys
          "${aws_s3_bucket.this.arn}/*"
        ]
      }
    }
  }
}
