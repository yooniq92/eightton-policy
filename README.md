# Eightton Policy

Code policy validation gate service.

## Overview

Validates code changes against configurable policy rules including:
- Protected path detection
- Layer rule enforcement (API/Service/Entity separation)
- Code convention checks (class inheritance, pattern presence)

## Build & Deploy

```bash
make build    # Build container image
make deploy   # Apply k8s manifests
make restart  # Rolling restart
make all      # Build + deploy + restart
```
