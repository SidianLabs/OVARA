# Control Plane Deployment

resource "kubernetes_namespace" "ovara" {
  metadata {
    name = "ovara-${var.environment}"
  }
}

resource "kubernetes_secret" "control_plane_env" {
  metadata {
    name      = "control-plane-env"
    namespace = kubernetes_namespace.ovara.metadata[0].name
  }

  data = {
    DATABASE_URL      = "postgres://ovara:${var.postgres_password}@postgres:5432/ovara_control"
    JWT_SECRET        = var.jwt_secret
    OPERATOR_API_KEY  = var.operator_api_key
    NODE_ENV          = var.environment
    PORT              = "3000"
  }
}

resource "kubernetes_deployment" "control_plane" {
  metadata {
    name      = "control-plane"
    namespace = kubernetes_namespace.ovara.metadata[0].name
    labels = {
      app     = "ovara"
      component = "control-plane"
    }
  }

  spec {
    replicas = 2

    selector {
      match_labels = {
        app     = "ovara"
        component = "control-plane"
      }
    }

    template {
      metadata {
        labels = {
          app     = "ovara"
          component = "control-plane"
        }
      }

      spec {
        container {
          name  = "control-plane"
          image = var.control_plane_image
          port {
            container_port = 3000
            protocol       = "TCP"
          }
          env_from {
            secret_ref {
              name = kubernetes_secret.control_plane_env.metadata[0].name
            }
          }
          liveness_probe {
            http_get {
              path = "/health"
              port = 3000
            }
            initial_delay_seconds = 15
            period_seconds        = 10
          }
          readiness_probe {
            http_get {
              path = "/health"
              port = 3000
            }
            initial_delay_seconds = 5
            period_seconds        = 5
          }
          resources {
            requests = {
              cpu    = "250m"
              memory = "256Mi"
            }
            limits = {
              cpu    = "1"
              memory = "512Mi"
            }
          }
        }
      }
    }
  }
}

resource "kubernetes_service" "control_plane" {
  metadata {
    name      = "control-plane"
    namespace = kubernetes_namespace.ovara.metadata[0].name
  }

  spec {
    selector = {
      app     = "ovara"
      component = "control-plane"
    }

    port {
      port        = 80
      target_port = 3000
      protocol    = "TCP"
    }
  }
}
