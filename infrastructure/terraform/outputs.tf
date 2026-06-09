# Outputs

output "namespace" {
  value = kubernetes_namespace.ovara.metadata[0].name
}

output "control_plane_endpoint" {
  value = "http://${kubernetes_service.control_plane.metadata[0].name}.${kubernetes_namespace.ovara.metadata[0].name}.svc.cluster.local"
}

output "gateway_endpoint" {
  value = "http://${kubernetes_service.gateway.metadata[0].name}.${kubernetes_namespace.ovara.metadata[0].name}.svc.cluster.local"
}

output "postgres_endpoint" {
  value = "${kubernetes_service.postgres.metadata[0].name}.${kubernetes_namespace.ovara.metadata[0].name}.svc.cluster.local:5432"
}

output "region" {
  value = var.region
}

output "gateway_replicas" {
  value = var.gateway_replicas
}
