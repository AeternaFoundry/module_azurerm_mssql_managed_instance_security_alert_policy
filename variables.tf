variable "mssql_managed_instance_security_alert_policies" {
  description = <<EOT
Map of mssql_managed_instance_security_alert_policies, attributes below
Required:
    - managed_instance_name
    - resource_group_name
Optional:
    - disabled_alerts
    - email_account_admins_enabled
    - email_addresses
    - enabled
    - retention_days
    - storage_account_access_key
    - storage_account_access_key_key_vault_id (alternative to storage_account_access_key - read from Key Vault instead)
    - storage_account_access_key_key_vault_secret_name (alternative to storage_account_access_key - read from Key Vault instead)
    - storage_endpoint
EOT

  type = map(object({
    managed_instance_name                            = string
    resource_group_name                              = string
    disabled_alerts                                  = optional(set(string))
    email_account_admins_enabled                     = optional(bool)
    email_addresses                                  = optional(set(string))
    enabled                                          = optional(bool)
    retention_days                                   = optional(number)
    storage_account_access_key                       = optional(string)
    storage_account_access_key_key_vault_id          = optional(string)
    storage_account_access_key_key_vault_secret_name = optional(string)
    storage_endpoint                                 = optional(string)
  }))
  validation {
    condition = alltrue([
      for k, v in var.mssql_managed_instance_security_alert_policies : (
        length(v.resource_group_name) <= 90
      )
    ])
    error_message = "[from resourcegroups.ValidateName: invalid when len(value) > 90]"
  }
  validation {
    condition = alltrue([
      for k, v in var.mssql_managed_instance_security_alert_policies : (
        !endswith(v.resource_group_name, ".")
      )
    ])
    error_message = "[from resourcegroups.ValidateName: must not end with \".\"]"
  }
  validation {
    condition = alltrue([
      for k, v in var.mssql_managed_instance_security_alert_policies : (
        length(v.resource_group_name) != 0
      )
    ])
    error_message = "[from resourcegroups.ValidateName: invalid when len(value) == 0]"
  }
  validation {
    condition = alltrue([
      for k, v in var.mssql_managed_instance_security_alert_policies : (
        v.disabled_alerts == null || (alltrue([for x in v.disabled_alerts : contains(["Sql_Injection", "Sql_Injection_Vulnerability", "Access_Anomaly", "Data_Exfiltration", "Unsafe_Action", "Brute_Force"], x)]))
      )
    ])
    error_message = "must be one of: Sql_Injection, Sql_Injection_Vulnerability, Access_Anomaly, Data_Exfiltration, Unsafe_Action, Brute_Force"
  }
  validation {
    condition = alltrue([
      for k, v in var.mssql_managed_instance_security_alert_policies : (
        v.retention_days == null || (v.retention_days >= 0)
      )
    ])
    error_message = "must be at least 0"
  }
  validation {
    condition = alltrue([
      for k, v in var.mssql_managed_instance_security_alert_policies : (
        v.storage_account_access_key == null || (length(v.storage_account_access_key) > 0)
      )
    ])
    error_message = "must not be empty"
  }
  validation {
    condition = alltrue([
      for k, v in var.mssql_managed_instance_security_alert_policies : (
        v.storage_endpoint == null || (length(v.storage_endpoint) > 0)
      )
    ])
    error_message = "must not be empty"
  }
  # Note: 2 additional provider-side validators are enforced at apply time but not mirrored as validation{} blocks here (bespoke or non-mechanically-translatable).
}

