module "assert_single_kms_key" {
  source        = "Invicton-Labs/assertion/null"
  version       = "~>0.2.8"
  condition     = !(var.create_new_kms_key == true && var.create_replica_kms_key == true)
  error_message = "If `create_new_kms_key` is `true`, `create_replica_kms_key` cannot be `true`."
}

module "assert_no_existing_kms_if_new" {
  source        = "Invicton-Labs/assertion/null"
  version       = "~>0.2.8"
  condition     = !(var.create_new_kms_key == true && var.kms_key_arn != null)
  error_message = "If `create_new_kms_key` is `true`, `kms_key_arn` must be `null`."
}

module "assert_source_kms_key" {
  source  = "Invicton-Labs/assertion/null"
  version = "~>0.2.8"
  depends_on = [
    module.assert_single_kms_key,
    module.assert_no_existing_kms_if_new,
  ]
  condition     = !(var.create_replica_kms_key == true && var.kms_key_arn == null)
  error_message = "If `create_replica_kms_key` is `true`, `kms_key_arn` must also be provided."
}
