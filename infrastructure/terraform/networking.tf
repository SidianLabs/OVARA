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
        # Control plane (Fastify, cloud/control-plane/src/server.ts) serves
        # exactly these prefixes; every other /v1/* route is served by the
        # runtime gateway.
        dynamic "path" {
          for_each = [
            "/v1/tenants",
            "/v1/organizations",
            "/v1/gateways",
            "/v1/policies",
            "/v1/revocations",
            "/v1/api-keys",
            "/v1/distribution",
            "/health",
          ]
          content {
            path      = path.value
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
        path {
          path      = "/v1"
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

    # DNS — required to resolve the postgres service name.
    egress {
      to {
        namespace_selector {
          match_labels = {
            name = "kube-system"
          }
        }
      }
      ports {
        port     = "53"
        protocol = "UDP"
      }
      ports {
        port     = "53"
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

    # DNS — without kube-dns egress the gateway cannot resolve
    # control-plane.<ns>.svc.cluster.local (or any other name).
    egress {
      to {
        namespace_selector {
          match_labels = {
            name = "kube-system"
          }
        }
      }
      ports {
        port     = "53"
        protocol = "UDP"
      }
      ports {
        port     = "53"
        protocol = "TCP"
      }
    }
    # NOTE: additional egress will be needed for any external control
    # plane, OTLP collector, or NATS endpoint the gateway is configured
    # to reach — this policy currently permits only cluster DNS and
    # control-plane pods.
  }
}
