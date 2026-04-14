# NXP eIQ Secure ML Pipeline Demo (Python + Animated HTML)

## 1) Run the Python end-to-end backend simulation

```bash
python3 examples/nxp_secure_ml_pipeline_demo.py
```

This script demonstrates:

1. **Artifact scanning**
   - Scans model files (`.tflite`, `.onnx`, etc.)
   - Computes SHA-256, size, entropy
   - Flags suspicious metadata content (potential embedded secrets)

2. **Deployment workflow policy gate**
   - Checks secure boot policy
   - Rejects debug firmware for production
   - Verifies signed deployment manifest (HMAC demo)

3. **Secure inference API**
   - `POST /infer` protected by:
     - API key
     - timestamp freshness window
     - nonce replay protection
     - HMAC request signing

4. **Runtime monitoring**
   - Detects model file hash mismatch (integrity/tamper signal)
   - Detects prediction anomalies via z-score drift check

## 2) Open the animated scenario walkthrough (HTML)

Open this file in any browser:

```bash
examples/nxp_secure_ml_pipeline_animated.html
```

The animation explains the whole lifecycle visually with:
- stage-by-stage highlights for scan/gate/API/monitoring,
- moving model/API packet flow,
- live event logs and security decisions,
- interactive controls (start/pause/reset),
- tamper injection (hash mismatch), and
- output-drift injection with animated score graph + z-score alerting.

> This is an educational skeleton. For production on i.MX 93 / i.MX 95, replace the toy runtime
> with actual eIQ/TensorFlow Lite/ONNX Runtime integrations and use device-backed key storage.
