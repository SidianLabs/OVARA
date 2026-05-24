# Policy Examples

```yaml
agent: deploy-agent

allow:
  - deploy:staging

deny:
  - deploy:production

require_approval:
  - deploy:critical

conditions:
  min_trust_score: 0.92
  verified_environment: true
```

