# 🔧 Troubleshooting & FAQ

Quick solutions for the most common issues when running Firedamp.

---

### 1. `Permission denied while trying to connect to Docker daemon`
**Cause:** Your current user account does not have permission to access `/var/run/docker.sock`.

**Fix:**
Add your user to the `docker` group:
```bash
sudo usermod -aG docker $USER
newgrp docker
```
*Or run Firedamp against an existing instance without Docker:*
```bash
firedamp scan --target-url http://localhost:8080
```

---

### 2. `Baseline warning: Alice could not retrieve her own canaries`
**Cause:** Before testing Bob (the attacker), Firedamp runs a baseline check as Alice to make sure the target platform actually indexed her files. If this warning appears:
- The vector embedding process took longer than expected.
- Or Open WebUI's embedding model is offline/unreachable.

**Fix:**
- Ensure the embedding model or Ollama instance is active.
- When running in Docker, pass `--cpu-only` so Open WebUI defaults to its fast built-in CPU SentenceTransformer instead of waiting for external LLM servers.

---

### 3. Docker Container Port Conflicts
**Cause:** Port `8080` is already bound by another local service.

**Fix:**
Firedamp automatically searches for an open ephemeral port by default. If you need a specific port or are testing an existing instance, supply `--target-url`:
```bash
firedamp scan --target-url http://localhost:3000
```

---

### 4. Running Without GPU Hardware
**Fix:**
Use the `--cpu-only` flag:
```bash
firedamp scan --target openwebui --cpu-only
```
This tells Firedamp to configure the container with `ENABLE_OLLAMA_API=False` and utilize CPU-only embeddings, eliminating all VRAM and GPU requirements.

