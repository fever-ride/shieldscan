variable "project_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "admin_email" {
  description = "Admin user email (leave empty to skip user creation)"
  type        = string
  default     = ""
}

variable "admin_temp_password" {
  description = "Temporary password for admin user"
  type        = string
  sensitive   = true
  default     = "TempPass1!"
}