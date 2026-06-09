# Gateway Ingress and NetworkPolicy

resource "kubernetes_ingress_v1" "api" {
  metadata {
    name      = "ovara-api"
    namespace = kubernetes_namespace.ovara.metadata[0].name
    annotations = {
      "nginx.ingress.kubernetes.io/ssl-redirect"    = "true"
      "nginx.ingress.kubernetes.io/proxy-body-size" = "10m"
      "cert-manager.io/cluster-issuer"              = "letsencrypt-prod"
    }
  }

  spec {
    ingress_class_name = "nginx"

    rule {
      host = "api.${var.environment}.ovara.io"
      http {
        path {
          path      = "/v1/runtime"
          path_type = "Prefix"
          backend {
            service {
              name = kubernetes_service.gateway.metadata[0].name
              port {
                number = 80
              }
            }
          }
        }
        path {
          path      = "/v1"
          path_type = "Prefix"
          backend {
            service {
              name = kubernetes_service.control_plane.metadata[0].name
              port {
                number = 80
              }
            }
          }
        }
      }
    }

    tls {
      hosts       = ["api.${var.environment}.ovara.io"]
      secret_name = "ovara-api-tls"
    }
  }
}

resource "kubernetes_network_policy" "control_plane_isolate" {
  metadata {
    name      = "control-plane-isolate"
    namespace = kubernetes_namespace.ovara.metadata[0].name
  }

  spec {
    pod_selector {
      match_labels = {
        component = "control-plane"
      }
    }

    policy_types = ["Ingress", "Egress"]

    ingress {
      from {
        pod_selector {
          match_labels = {
            component = "gateway"
          }
        }
      }
      from {
        namespace_selector {
          match_labels = {
            name = "ingress-nginx"
          }
        }
      }
    }

    egress {
      to {
        pod_selector {
          match_labels = {
            component = "postgres"
          }
        }
      }
      ports {
        port     = "5432"
        protocol = "TCP"
      }
    }
  }
}

resource "kubernetes_network_policy" "gateway_isolate" {
  metadata {
    name      = "gateway-isolate"
    namespace = kubernetes_namespace.ovara.metadata[0].name
  }

  spec {
    pod_selector {
      match_labels = {
        component = "gateway"
      }
    }

    policy_types = ["Ingress", "Egress"]

    ingress {
      from {
        namespace_selector {
          match_labels = {
            name = "ingress-nginx"
          }
        }
      }
    }

    egress {
      to {
        pod_selector {
          match_labels = {
            component = "control-plane"
          }
        }
      }
    }
  }
}
