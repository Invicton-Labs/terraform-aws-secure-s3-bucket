variable "region" {
  description = "The region to deploy the bucket in. If `null`, the provider's region will be used."
  type        = string
  default     = null
  nullable    = true
}

variable "name" {
  description = "The name to use for the bucket."
  type        = string
  nullable    = false
}

variable "versioned" {
  description = "Whether the bucket should be versioned."
  type        = bool
  nullable    = false
}

variable "mfa_delete_enabled" {
  description = "Whether MFA Delete should be enabled."
  type        = bool
  default     = false
  nullable    = false
}

variable "mfa_delete_serial_number" {
  description = "The serial number of the MFA device to use for MFA delete."
  type        = string
  default     = null
  nullable    = true
}

variable "mfa_delete_token_code" {
  description = "The token code currently showing on the MFA device to use for MFA delete."
  type        = string
  default     = null
  nullable    = true
}

variable "bucket_policy_json_documents" {
  description = "A list of JSON-encoded policy documents to apply to the bucket. The placeholder \"{BUCKET_ARN}\" can be used to reference the ARN of the bucket the policy is being applied to."
  type        = list(string)
  default     = []
  nullable    = false
}

variable "kms_key_arn" {
  description = "The ARN of the KMS key to use for this bucket. If not provided, AES256 encryption will be enforced instead."
  type        = string
  default     = null
}

variable "create_new_kms_key" {
  description = "Whether to create a new KMS key for use with this bucket. If `kms_key_arn` is not provided (null), a new key will be created. If `kms_key_arn` is provided, a replica of that key will be created."
  type        = bool
  default     = false
  nullable    = false
}

variable "create_replica_kms_key" {
  description = "Whether to create a replica key, using `kms_key_arn` as the source key."
  type        = bool
  default     = false
  nullable    = false
}

variable "kms_key_policy_json_documents" {
  description = "A list of JSON-encoded policy documents to apply to the KMS key, if one should be created."
  type        = list(string)
  default     = []
  nullable    = false
}

variable "enable_transfer_acceleration" {
  description = "Whether to enable transfer acceleration for this bucket."
  type        = bool
  default     = false
  nullable    = false
}

variable "block_public_acls" {
  description = "The `block_public_acls` value of an `aws_s3_bucket_public_access_block` resource that is applied to this bucket."
  type        = bool
  default     = true
  nullable    = false
}

variable "block_public_policy" {
  description = "The `block_public_policy` value of an `aws_s3_bucket_public_access_block` resource that is applied to this bucket."
  type        = bool
  default     = true
  nullable    = false
}

variable "ignore_public_acls" {
  description = "The `ignore_public_acls` value of an `aws_s3_bucket_public_access_block` resource that is applied to this bucket."
  type        = bool
  default     = true
  nullable    = false
}

variable "restrict_public_buckets" {
  description = "The `restrict_public_buckets` value of an `aws_s3_bucket_public_access_block` resource that is applied to this bucket."
  type        = bool
  default     = true
  nullable    = false
}

variable "object_ownership" {
  description = "The `rule.object_ownership` value of an `aws_s3_bucket_ownership_controls` resource that is applied to this bucket."
  type        = string
  default     = "BucketOwnerEnforced"
  nullable    = false
}

variable "append_region_suffix" {
  description = "If `true`, a suffix in the form of `-{region_name}` will be appended to the bucket name. This is convenient if you're creating buckets in multiple regions and don't want to manually specify the region name in each one for uniqueness."
  type        = bool
  default     = false
  nullable    = false
}

variable "object_lock_enabled" {
  description = "Indicates whether this bucket has an Object Lock configuration enabled."
  type        = bool
  default     = false
  nullable    = false
}

variable "force_destroy" {
  description = "A boolean that indicates all objects (including any locked objects) should be deleted from the bucket so that the bucket can be destroyed without error."
  type        = bool
  default     = false
  nullable    = false
}

variable "force_allow_cloudtrail_digest" {
  description = "Whether to allow AES256 (AWS-managed key) encryption for paths checked by CloudTrail digest writers. Even when a bucket and a CloudTrail are both set to use KMS encryption, digests are still written using AWS-managed key AES256 encryption (). This variable only has an effect when the `kms_key_id` variable is provided and not `null`."
  type        = bool
  default     = false
  nullable    = false
}

variable "enable_shield_drt_access" {
  description = "Whether to add a policy for Shield Advanced DRT access. If the `aws_shield_drt_access_log_bucket_association` resource is used for this bucket, it will modify the bucket policy. This variable causes the same policy to be added, preventing them from conflicting."
  type        = bool
  default     = false
  nullable    = false
}

variable "cors_rules" {
  description = "A list of CORS rules to apply to the S3 bucket."
  type = list(object({
    allowed_headers = optional(list(string))
    allowed_methods = list(string)
    allowed_origins = list(string)
    expose_headers  = optional(list(string))
    id              = optional(string)
    max_age_seconds = optional(number)
  }))
  nullable = false
  default  = []
}

variable "tags_s3_bucket" {
  description = "A map of tags to apply to the S3 bucket."
  type        = map(string)
  nullable    = true
  default     = null
}
