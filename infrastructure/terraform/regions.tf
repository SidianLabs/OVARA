# Regional Topology Configuration
#
# Deploy multiple regional gateway clusters with unique configuration.
# Each region has its own HPA, policy version, and operator token.
#
# Usage:
#   terraform apply -var-file="regions/us-east-1.tfvars"

locals {
  regions = {
    "us-east-1" = {
      replicas        = 5
      policy_version  = "v1-us-east-1"
      region_tag      = "us-east"
    }
    "us-west-2" = {
      replicas        = 3
      policy_version  = "v1-us-west-2"
      region_tag      = "us-west"
    }
    "eu-west-1" = {
      replicas         = 4
      policy_version   = "v1-eu-west-1"
      region_tag       = "eu-west"
    }
    "ap-southeast-1" = {
      replicas         = 3
      policy_version   = "v1-ap-southeast-1"
      region_tag       = "ap-se"
    }
  }
}

# Multi-region topology: deploy gateways in all regions
#
# module "gateway_us_east" {
#   source    = "./modules/gateway-region"
#   region    = "us-east-1"
#   replicas  = 5
#   control_plane_endpoint = kubernetes_service.control_plane.metadata[0].name
# }
#
# module "gateway_us_west" {
#   source    = "./modules/gateway-region"
#   region    = "us-west-2"
#   replicas  = 3
#   control_plane_endpoint = kubernetes_service.control_plane.metadata[0].name
# }
