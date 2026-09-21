# Regional Runtime Gateways

# Gateway config contains secrets (operator_tokens, receipt_signing_key),
# so it lives in a Secret, not a ConfigMap. Keys not present in the
# gateway Config struct (runtime/gateway/internal/config/config.go) —
# e.g. environment/region/control_plane_url — were removed: the gateway
# ignores them and control-plane enrollment is driven by OVARA_* env
# plus on-disk enrollment state.
resource "kubernetes_secret" "gateway_config" {
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
      policy_file          = "/etc/ovara-policy/policy.json"
      fail_closed          = true
      auth_enabled         = true
      operator_tokens      = var.operator_tokens
      log_level            = "info"
      receipt_signing_key  = var.receipt_signing_key
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
            name  = "OVARA_CONFIG"
            value = "/etc/ovara/config.json"
          }
          volume_mount {
            name       = "config"
            mount_path = "/etc/ovara"
            read_only  = true
          }
          volume_mount {
            name       = "policy"
            mount_path = "/etc/ovara-policy"
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
          secret {
            secret_name = kubernetes_secret.gateway_config.metadata[0].name
          }
        }
        volume {
          name = "policy"
          config_map {
            name = kubernetes_config_map.gateway_policy.metadata[0].name
          }
        }
        volume {
          name = "data"
          # Receipts, approvals, events, and audit files live under
          # /var/data/ovara — a PVC is required so they survive pod
          # restarts (empty_dir would lose signed receipts).
          persistent_volume_claim {
            claim_name = kubernetes_persistent_volume_claim.gateway_data.metadata[0].name
          }
        }
      }
    }
  }
}

# Default file policy mounted at /etc/ovara-policy/policy.json.
# Note: file-loaded rules honor only action_type / environment /
# allow / deny / escalate — `conditions` and `min_trust_*` fields are
# parsed-then-dropped by LoadStoreFromFile today.
resource "kubernetes_config_map" "gateway_policy" {
  metadata {
    name      = "gateway-policy"
    namespace = kubernetes_namespace.ovara.metadata[0].name
  }

  data = {
    "policy.json" = jsonencode({
      version = "v1-prod"
      rules = [
        {
          action_type = "*"
          environment = var.environment
          escalate    = true
          description = "Default: escalate all actions for approval"
        }
      ]
    })
  }
}

resource "kubernetes_persistent_volume_claim" "gateway_data" {
  metadata {
    name      = "gateway-data"
    namespace = kubernetes_namespace.ovara.metadata[0].name
  }

  spec {
    access_modes = ["ReadWriteOnce"]
    resources {
      requests = {
        storage = "10Gi"
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
