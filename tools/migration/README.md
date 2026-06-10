# Ovara Migration Utilities

## Import: local → cloud
```bash
ovara migrate import --source var/data/ --target https://control-plane.ovara.io
```

## Export: cloud → local
```bash
ovara migrate export --source https://control-plane.ovara.io --target var/data/
```

## Config conversion
```bash
ovara migrate config --from legacy-config.json --to v1-config.json
```
