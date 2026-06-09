terraform {
  required_version = ">= 1.5"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.30"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "kubernetes" {
  config_path = var.kubeconfig_path
}

variable "kubeconfig_path" {
  type    = string
  default = "~/.kube/config"
}

variable "environment" {
  type    = string
  default = "production"
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "gateway_replicas" {
  type    = number
  default = 3
}

variable "gateway_image" {
  type    = string
  default = "ovara/gateway:latest"
}

variable "control_plane_image" {
  type    = string
  default = "ovara/control-plane:latest"
}

variable "postgres_password" {
  type      = string
  sensitive = true
}

variable "jwt_secret" {
  type      = string
  sensitive = true
}

variable "operator_api_key" {
  type      = string
  sensitive = true
}

resource "random_id" "cluster_suffix" {
  byte_length = 4
}
