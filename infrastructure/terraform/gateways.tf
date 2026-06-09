# Regional Runtime Gateways

resource "kubernetes_config_map" "gateway_config" {
  metadata {
    name      = "gateway-config"
    namespace = kubernetes_namespace.ovara.metadata[0].name
  }

  data = {
    "config.json" = jsonencode({
      server_port          = "8080"
      gateway_name         = "production-gateway"
      gateway_version      = "1.0.0"
      policy_version       = "v1-prod"
      environment          = var.environment
      region               = var.region
      policy_file          = "/etc/ovara/policy.json"
      fail_closed          = true
      auth_enabled         = true
      log_level            = "info"
      receipt_signing_key  = var.jwt_secret
      control_plane_url    = "http://control-plane.${kubernetes_namespace.ovara.metadata[0].name}.svc.cluster.local"
      control_plane_api_key = var.operator_api_key
      heartbeat_interval_secs = 30
      policy_refresh_interval = 60
      decision_log_file    = "/var/data/ovara/decisions.jsonl"
      events_file          = "/var/data/ovara/events.jsonl"
      continuations_file   = "/var/data/ovara/continuations.jsonl"
      execution_file       = "/var/data/ovara/executions.jsonl"
      receipts_file        = "/var/data/ovara/receipts.json"
      approvals_file       = "/var/data/ovara/approvals.json"
      capabilities_file    = "/var/data/ovara/capabilities.json"
      enrollment_file      = "/var/data/ovara/enrollment.json"
      execution_working_dir = "/tmp/ovara-exec"
      execution_stdout_limit_bytes = 1048576
      execution_stderr_limit_bytes = 262144
      sla_approval_max_age_min = 30
      sla_retryable_max_age_min = 60
      sla_executing_max_age_min = 5
      stuck_executing_sweep_interval_secs = 300
      stuck_executing_recovery_threshold_min = 30
    })
  }
}

resource "kubernetes_deployment" "gateway" {
  metadata {
    name      = "gateway"
    namespace = kubernetes_namespace.ovara.metadata[0].name
    labels = {
      app     = "ovara"
      component = "gateway"
      region  = var.region
    }
  }

  spec {
    replicas = var.gateway_replicas

    selector {
      match_labels = {
        app      = "ovara"
        component = "gateway"
      }
    }

    template {
      metadata {
        labels = {
          app      = "ovara"
          component = "gateway"
          region   = var.region
        }
      }

      spec {
        container {
          name  = "gateway"
          image = var.gateway_image
          port {
            container_port = 8080
            protocol       = "TCP"
            name          = "http"
          }
          env {
            name  = "OVARA_ENVIRONMENT"
            value = var.environment
          }
          env {
            name  = "OVARA_REGION"
            value = var.region
          }
          env {
            name  = "OVARA_CONFIG"
            value = "/etc/ovara/config.json"
          }
          volume_mount {
            name       = "config"
            mount_path = "/etc/ovara"
            read_only  = true
          }
          volume_mount {
            name       = "data"
            mount_path = "/var/data/ovara"
          }
          liveness_probe {
            http_get {
              path = "/v1/runtime/health"
              port = 8080
            }
            initial_delay_seconds = 15
            period_seconds        = 10
          }
          readiness_probe {
            http_get {
              path = "/v1/runtime/health"
              port = 8080
            }
            initial_delay_seconds = 5
            period_seconds        = 5
          }
          resources {
            requests = {
              cpu    = "500m"
              memory = "256Mi"
            }
            limits = {
              cpu    = "2"
              memory = "1Gi"
            }
          }
        }

        volume {
          name = "config"
          config_map {
            name = kubernetes_config_map.gateway_config.metadata[0].name
          }
        }
        volume {
          name = "data"
          empty_dir {}
        }
      }
    }
  }
}

resource "kubernetes_service" "gateway" {
  metadata {
    name      = "gateway"
    namespace = kubernetes_namespace.ovara.metadata[0].name
  }

  spec {
    selector = {
      app      = "ovara"
      component = "gateway"
    }

    port {
      port        = 80
      target_port = 8080
      protocol    = "TCP"
      name        = "http"
    }

    type = "ClusterIP"
  }
}

resource "kubernetes_horizontal_pod_autoscaler" "gateway" {
  metadata {
    name      = "gateway-hpa"
    namespace = kubernetes_namespace.ovara.metadata[0].name
  }

  spec {
    scale_target_ref {
      api_version = "apps/v1"
      kind        = "Deployment"
      name        = kubernetes_deployment.gateway.metadata[0].name
    }

    min_replicas = var.gateway_replicas
    max_replicas = 20

    metric {
      type = "Resource"
      resource {
        name = "cpu"
        target {
          type               = "Utilization"
          average_utilization = 70
        }
      }
    }
  }
}
