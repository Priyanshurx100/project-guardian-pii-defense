# Deployment Strategy — Project Guardian 2.0 (Real-time PII Defense)

## Goal
Stop PII leaks in **real time** across ingress logs, 3rd-party integrations, and internal tools without adding noticeable latency.

![Architecture](docs/architecture.png)

## Where it runs (recommended)
**API Gateway Plugin / Sidecar filter at the ingress tier** (e.g., NGINX, Kong, Envoy).  
All inbound/outbound traffic and logs pass through here, so it’s the single most effective enforcement point.

### Why gateway/sidecar?
- **Coverage:** Every microservice & integration flows through it.
- **Low latency:** Regex/rule logic is sub-millisecond typical per payload.
- **Language-agnostic:** No app code changes required.
- **Scalable:** Horizontal scale with gateway replicas; sidecar per-pod if needed.
- **Cost-effective:** No heavy ML inference path in the hot loop.

## Data flow
1. **Request/Response** enters the Gateway.
2. **PII Filter** (our logic) scans JSON/text fields:
   - **A-class (standalone PII)**: phone (10d), Aadhaar (12d), passport (L+7d), UPI (`user@provider`) → **always** redact/mask.
   - **B-class (combinatorial)**: full name, email, address, device_id/IP → **redact only when ≥2 appear together**.
3. Sanitized payload is forwarded to services; sanitized logs go to logging/SIEM.

## Deployment options
- **Kubernetes Ingress**: Envoy/NGINX/Kong plugin; or **sidecar** container injected to sensitive services.
- **Reverse proxy layer**: NGINX `lua`/`njs` calling a local Python service; or embed Python via WSGI/ASGI.
- **Standalone redaction microservice**: `/sanitize` endpoint; gateway routes logs/payloads through it (adds a hop but easy to adopt).

## Performance & tuning
- Use **compiled regex** + bounded payload size.
- Stream payloads; short-circuit once PII is found and masked.
- Skip known numeric ID keys (order_id, txn_id, etc.) to reduce false positives.
- Async export of sanitized logs to SIEM/warehouse.

## Monitoring
- Emit counters: detections by type, redaction rate, false-positive appeals.
- Sample a tiny % of sanitized vs. raw (masked) for QA in a secure enclave.

## Security & privacy
- All redaction is **in-memory**; no raw PII persisted.
- Strict allowlist of fields to log; redact before logging.
- Versioned rules; change control via GitOps.

## Future work
- Optional hybrid NER for free-text fields (offline or nearline).
- Policy packs per region (GDPR/DPDP).
- Canary mode + diff view before enforcing globally.
