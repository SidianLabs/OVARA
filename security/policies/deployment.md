# Ovara Security Policy Templates

## Gateway Deployment
- Run as non-root user (uid 1000)
- Read-only root filesystem
- No privileged escalation (allowPrivilegeEscalation: false)
- Drop all capabilities, add only NET_BIND_SERVICE
- Seccomp profile: RuntimeDefault
- AppArmor/SELinux profile enforced

## Control Plane
- TLS 1.3 minimum
- mTLS for gateway-to-control-plane communication
- API keys rotated every 90 days
- All secrets in K8s Secrets (never in config maps)
- NetworkPolicy: deny-all by default, explicit allow rules

## Data at Rest
- PostgreSQL: encryption at rest (LUKS or KMS)
- Receipt storage: AES-256-GCM encryption
- Backup encryption required

## Audit
- All admin actions logged to audit_log table
- API key usage logged with IP and user agent
- Policy changes versioned with rollback capability
