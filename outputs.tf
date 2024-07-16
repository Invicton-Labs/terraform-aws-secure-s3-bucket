//==================================================
//     Outputs that match the input variables
//==================================================
output "name" {
  description = "The value of the `name` input variable."
  value       = var.name
}
output "versioned" {
  description = "The value of the `versioned` input variable."
  value       = var.versioned
}
output "mfa_delete_enabled" {
  description = "The value of the `mfa_delete_enabled` input variable, or the default value if the input was `null`."
  value       = var.mfa_delete_enabled
}
output "mfa_delete_serial_number" {
  description = "The value of the `mfa_delete_serial_number` input variable."
  value       = var.mfa_delete_serial_number
}
output "mfa_delete_token_code" {
  description = "The value of the `mfa_delete_token_code` input variable."
  value       = var.mfa_delete_token_code
}
output "object_lock_enabled" {
  description = "The value of the `object_lock_enabled` input variable, or the default value if the input was `null`."
  value       = var.object_lock_enabled
}
output "force_destroy" {
  description = "The value of the `force_destroy` input variable, or the default value if the input was `null`."
  value       = var.force_destroy
}
output "create_new_kms_key" {
  description = "The value of the `create_new_kms_key` input variable, or the default value if the input was `null`."
  value       = var.create_new_kms_key
}
output "create_replica_kms_key" {
  description = "The value of the `create_replica_kms_key` input variable, or the default value if the input was `null`."
  value       = var.create_replica_kms_key
}
output "kms_key_policy_json_documents" {
  description = "The value of the `kms_key_policy_json_documents` input variable, or the default value if the input was `null`."
  value       = var.kms_key_policy_json_documents
}
output "bucket_policy_json_documents" {
  description = "The value of the `bucket_policy_json_documents` input variable, or the default value if the input was `null`."
  value       = var.bucket_policy_json_documents
}
output "enable_transfer_acceleration" {
  description = "The value of the `enable_transfer_acceleration` input variable, or the default value if the input was `null`."
  value       = var.enable_transfer_acceleration
}
output "block_public_acls" {
  description = "The value of the `block_public_acls` input variable, or the default value if the input was `null`."
  value       = var.block_public_acls
}
output "block_public_policy" {
  description = "The value of the `block_public_policy` input variable, or the default value if the input was `null`."
  value       = var.block_public_policy
}
output "ignore_public_acls" {
  description = "The value of the `ignore_public_acls` input variable, or the default value if the input was `null`."
  value       = var.ignore_public_acls
}
output "restrict_public_buckets" {
  description = "The value of the `restrict_public_buckets` input variable, or the default value if the input was `null`."
  value       = var.restrict_public_buckets
}
output "object_ownership" {
  description = "The value of the `object_ownership` input variable, or the default value if the input was `null`."
  value       = var.object_ownership
}
output "append_region_suffix" {
  description = "The value of the `append_region_suffix` input variable, or the default value if the input was `null`."
  value       = var.append_region_suffix
}
output "force_allow_cloudtrail_digest" {
  description = "The value of the `force_allow_cloudtrail_digest` input variable, or the default value if the input was `null`."
  value       = var.force_allow_cloudtrail_digest
}
output "tags_s3_bucket" {
  description = "The value of the `tags_s3_bucket` input variable."
  value       = var.tags_s3_bucket
}

//==================================================
//       Outputs generated by this module
//==================================================
output "region" {
  description = "The name of the region that the bucket was created in."
  value       = data.aws_region.current.name
}

output "account_id" {
  description = "The ID of the AWS account that the bucket was created in."
  value       = data.aws_caller_identity.current.account_id
}

output "bucket" {
  description = "The `aws_s3_bucket` resource that was created."
  value       = aws_s3_bucket.this
}

output "outbound_replication_policy_json" {
  description = "A JSON policy that grants permission to replicate objects out of this bucket."
  value       = data.aws_iam_policy_document.outbound_replication.json
}

output "inbound_replication_policy_json" {
  description = "A JSON policy that grants permission to replicate objects into this bucket."
  value       = data.aws_iam_policy_document.inbound_replication.json
}

output "kms_key_arn" {
  description = "The ARN of the KMS key that was used for the default encryption of the bucket, if any."
  value       = local.used_kms_key_arn
}

output "kms_alias_name" {
  description = "The name of the KMS alias that was created for the new KMS key/replica, if any."
  value       = length(aws_kms_alias.this) > 0 ? aws_kms_alias.this[0].name : null
}

output "kms_alias_arn" {
  description = "The ARN of the KMS alias that was created for the new KMS key/replica, if any."
  value       = length(aws_kms_alias.this) > 0 ? aws_kms_alias.this[0].arn : null
}

output "bucket_arn_placeholder" {
  description = "A string that, when included in a bucket policy passed into this module, will be replaced by the ARN of the bucket that was created by this module."
  value       = local.bucket_arn_placeholder
}

output "bucket_write_policy_document" {
  description = "An IAM policy document that grants permissions to write objects to the bucket."
  value       = data.aws_iam_policy_document.write.json
}

output "bucket_delete_policy_document" {
  description = "An IAM policy document that grants permissions to delete objects (only current versions) from the bucket."
  value       = data.aws_iam_policy_document.delete.json
}

output "bucket_read_policy_document" {
  description = "An IAM policy document that grants permissions to list and read all objects in the bucket, along with their versions, attributes, and tags."
  value       = data.aws_iam_policy_document.read.json
}

output "complete" {
  depends_on = [
    aws_s3_bucket_accelerate_configuration.this
  ]
  description = "Always `true`, but doesn't return until everything in this module has been applied."
  value       = true
}
