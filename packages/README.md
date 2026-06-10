# Ovara Packages — Publishing

## npm Workspace
Root `packages/package.json` defines the monorepo workspace.

## Publishing Commands

```bash
# Publish SDK
cd sdk/typescript && npm publish --access public

# Publish integrations
cd integrations/mcp && npm publish --access public
cd integrations/langchain && npm publish --access public
```

## PyPI Publishing

```bash
cd sdk/python && python -m build && twine upload dist/*
```

## Go Module Publishing

```bash
# Identity module — usable standalone
cd identity && git tag identity/v0.1.0 && git push --tags

# Trust module — depends on identity
cd trust && git tag trust/v0.1.0 && git push --tags
```
