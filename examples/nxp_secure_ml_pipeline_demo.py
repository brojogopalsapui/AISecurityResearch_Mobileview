#!/usr/bin/env python3
"""
NXP eIQ-oriented secure ML workflow demonstration.

This script is intentionally self-contained (stdlib-only) and shows:
1) Security scanning for ML artifacts used in embedded deployment (e.g., i.MX 93 / i.MX 95).
2) Deployment workflow checks (manifest + policy gates).
3) Secure API pattern for on-device model integration.
4) Runtime monitoring for model integrity and anomaly detection.

It is educational code, not production-hardened.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import os
import pathlib
import random
import secrets
import statistics
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


# ----------------------------
# Utility helpers
# ----------------------------

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: pathlib.Path, chunk_size: int = 65536) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    length = len(data)

    import math

    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / length
            entropy -= p * math.log2(p)
    return entropy


# ----------------------------
# Artifact scanning
# ----------------------------

MODEL_EXTENSIONS = {".onnx", ".tflite", ".bin", ".nb", ".elf"}


@dataclass
class ArtifactFinding:
    severity: str
    code: str
    message: str
    file: str | None = None


@dataclass
class ArtifactReport:
    generated_at: str
    project: str
    scanned_dir: str
    files_scanned: int
    model_files: list[dict[str, Any]]
    findings: list[ArtifactFinding]

    def to_json(self) -> str:
        data = dataclasses.asdict(self)
        return json.dumps(data, indent=2)


class ArtifactSecurityScanner:
    """Scans model artifacts and metadata for basic risk signals."""

    def __init__(self, max_model_size_mb: int = 64):
        self.max_model_size_mb = max_model_size_mb

    def scan(self, project: str, artifacts_dir: pathlib.Path) -> ArtifactReport:
        findings: list[ArtifactFinding] = []
        model_files: list[dict[str, Any]] = []
        files_scanned = 0

        for path in artifacts_dir.rglob("*"):
            if not path.is_file():
                continue
            files_scanned += 1
            ext = path.suffix.lower()
            if ext in MODEL_EXTENSIONS:
                size_mb = path.stat().st_size / (1024 * 1024)
                file_hash = sha256_file(path)
                with path.open("rb") as f:
                    head = f.read(4096)
                entropy = shannon_entropy(head)

                model_info = {
                    "file": str(path.relative_to(artifacts_dir)),
                    "size_mb": round(size_mb, 3),
                    "sha256": file_hash,
                    "head_entropy": round(entropy, 3),
                }
                model_files.append(model_info)

                if size_mb > self.max_model_size_mb:
                    findings.append(
                        ArtifactFinding(
                            severity="high",
                            code="MODEL_TOO_LARGE",
                            message=(
                                f"Model {path.name} exceeds size policy "
                                f"({size_mb:.2f}MB > {self.max_model_size_mb}MB)."
                            ),
                            file=str(path),
                        )
                    )

                if entropy > 7.9:
                    findings.append(
                        ArtifactFinding(
                            severity="medium",
                            code="HIGH_ENTROPY_HEADER",
                            message=(
                                f"{path.name} has unusually high header entropy; "
                                "review for packed/encrypted unknown payloads."
                            ),
                            file=str(path),
                        )
                    )

            if path.name.endswith(".json"):
                self._scan_json_metadata(path, findings)

        if not model_files:
            findings.append(
                ArtifactFinding(
                    severity="medium",
                    code="NO_MODEL_FILES",
                    message="No model artifacts found; verify pipeline output path.",
                    file=None,
                )
            )

        return ArtifactReport(
            generated_at=utc_now_iso(),
            project=project,
            scanned_dir=str(artifacts_dir),
            files_scanned=files_scanned,
            model_files=model_files,
            findings=findings,
        )

    @staticmethod
    def _scan_json_metadata(path: pathlib.Path, findings: list[ArtifactFinding]) -> None:
        try:
            content = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            findings.append(
                ArtifactFinding(
                    severity="low",
                    code="INVALID_JSON",
                    message=f"Could not parse JSON metadata: {exc}",
                    file=str(path),
                )
            )
            return

        raw = json.dumps(content).lower()
        secret_markers = ["password", "apikey", "token", "private_key"]
        for marker in secret_markers:
            if marker in raw:
                findings.append(
                    ArtifactFinding(
                        severity="high",
                        code="POTENTIAL_SECRET_IN_METADATA",
                        message=f"Potential secret marker '{marker}' found in metadata.",
                        file=str(path),
                    )
                )
                break


# ----------------------------
# Deployment workflow checks
# ----------------------------

@dataclass
class DeploymentPolicy:
    secure_boot_required: bool = True
    allow_debug_firmware: bool = False
    min_model_version: int = 1
    require_signed_manifest: bool = True


class DeploymentWorkflowGuard:
    """Validates deployment manifests before embedded rollout."""

    def __init__(self, policy: DeploymentPolicy, signing_key: bytes):
        self.policy = policy
        self.signing_key = signing_key

    def verify_manifest(self, manifest: dict[str, Any]) -> list[ArtifactFinding]:
        findings: list[ArtifactFinding] = []

        if self.policy.secure_boot_required and not manifest.get("secure_boot", False):
            findings.append(
                ArtifactFinding(
                    severity="critical",
                    code="SECURE_BOOT_DISABLED",
                    message="Deployment rejected: secure boot is required.",
                )
            )

        if not self.policy.allow_debug_firmware and manifest.get("debug_firmware", False):
            findings.append(
                ArtifactFinding(
                    severity="high",
                    code="DEBUG_FIRMWARE_ENABLED",
                    message="Debug firmware must be disabled for production deployment.",
                )
            )

        if int(manifest.get("model_version", 0)) < self.policy.min_model_version:
            findings.append(
                ArtifactFinding(
                    severity="high",
                    code="MODEL_VERSION_TOO_OLD",
                    message="Model version does not meet minimum supported policy.",
                )
            )

        if self.policy.require_signed_manifest:
            supplied_sig = manifest.get("signature", "")
            computed_sig = self._compute_signature(manifest)
            if not supplied_sig or not hmac.compare_digest(supplied_sig, computed_sig):
                findings.append(
                    ArtifactFinding(
                        severity="critical",
                        code="INVALID_MANIFEST_SIGNATURE",
                        message="Manifest signature invalid or missing.",
                    )
                )

        return findings

    def _compute_signature(self, manifest: dict[str, Any]) -> str:
        canonical = {k: v for k, v in manifest.items() if k != "signature"}
        payload = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
        return hmac.new(self.signing_key, payload, hashlib.sha256).hexdigest()


# ----------------------------
# Model + monitoring
# ----------------------------

class EmbeddedModelRuntime:
    """A tiny stand-in for an eIQ-integrated runtime."""

    def __init__(self, model_path: pathlib.Path):
        self.model_path = model_path
        self.expected_hash = sha256_file(model_path)

    def infer_score(self, features: list[float]) -> float:
        # Deterministic toy score to simulate inference behavior.
        weighted = sum((i + 1) * x for i, x in enumerate(features))
        noise = (hash(tuple(round(v, 6) for v in features)) % 100) / 10000
        return 1 / (1 + pow(2.71828, -(weighted / (len(features) + 1)))) + noise


@dataclass
class MonitoringAlert:
    level: str
    reason: str
    detail: str
    at: str = field(default_factory=utc_now_iso)


class ModelIntegrityMonitor:
    """Checks model hash drift and output anomalies."""

    def __init__(self, runtime: EmbeddedModelRuntime, baseline_window: int = 40):
        self.runtime = runtime
        self.history = deque(maxlen=baseline_window)
        self.alerts: deque[MonitoringAlert] = deque(maxlen=200)
        self._lock = threading.Lock()

    def check_integrity(self) -> None:
        current_hash = sha256_file(self.runtime.model_path)
        if current_hash != self.runtime.expected_hash:
            self._push_alert(
                MonitoringAlert(
                    level="critical",
                    reason="model_tamper",
                    detail="On-device model hash mismatch detected.",
                )
            )

    def observe_prediction(self, score: float) -> None:
        with self._lock:
            if len(self.history) >= 10:
                mean = statistics.mean(self.history)
                stdev = statistics.pstdev(self.history) or 1e-6
                z = abs((score - mean) / stdev)
                if z > 4.0:
                    self.alerts.append(
                        MonitoringAlert(
                            level="high",
                            reason="prediction_anomaly",
                            detail=f"Prediction score z-score={z:.2f} exceeded threshold.",
                        )
                    )
            self.history.append(score)

    def recent_alerts(self) -> list[dict[str, str]]:
        with self._lock:
            return [dataclasses.asdict(a) for a in list(self.alerts)]

    def _push_alert(self, alert: MonitoringAlert) -> None:
        with self._lock:
            self.alerts.append(alert)


# ----------------------------
# Secure API
# ----------------------------

class SecureInferenceAPI:
    """Minimal API server with API key + body signature + freshness checks."""

    def __init__(self, host: str, port: int, runtime: EmbeddedModelRuntime, monitor: ModelIntegrityMonitor):
        self.host = host
        self.port = port
        self.runtime = runtime
        self.monitor = monitor
        self.api_key = secrets.token_hex(16)
        self.hmac_secret = secrets.token_bytes(32)
        self._seen_nonces: deque[str] = deque(maxlen=5000)

    def start(self) -> ThreadingHTTPServer:
        api = self

        class Handler(BaseHTTPRequestHandler):
            def _send_json(self, status: int, payload: dict[str, Any]) -> None:
                body = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self) -> None:  # noqa: N802
                if self.path != "/infer":
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                    return

                auth_key = self.headers.get("X-API-Key", "")
                ts = self.headers.get("X-Timestamp", "")
                nonce = self.headers.get("X-Nonce", "")
                signature = self.headers.get("X-Signature", "")

                if auth_key != api.api_key:
                    self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "bad_api_key"})
                    return

                if not ts or not nonce or not signature:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "missing_security_headers"})
                    return

                try:
                    req_ts = int(ts)
                except ValueError:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_timestamp"})
                    return

                if abs(time.time() - req_ts) > 30:
                    self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "request_expired"})
                    return

                if nonce in api._seen_nonces:
                    self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "replay_detected"})
                    return

                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                expected_sig = hmac.new(api.hmac_secret, ts.encode() + nonce.encode() + body, hashlib.sha256).hexdigest()
                if not hmac.compare_digest(signature, expected_sig):
                    self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "bad_signature"})
                    return

                api._seen_nonces.append(nonce)

                try:
                    payload = json.loads(body.decode("utf-8"))
                    features = payload["features"]
                    if not isinstance(features, list) or not all(isinstance(x, (int, float)) for x in features):
                        raise ValueError("features must be list[number]")
                except Exception as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "bad_payload", "detail": str(exc)})
                    return

                api.monitor.check_integrity()
                score = api.runtime.infer_score([float(x) for x in features])
                api.monitor.observe_prediction(score)
                alerts = api.monitor.recent_alerts()[-3:]

                self._send_json(
                    HTTPStatus.OK,
                    {
                        "score": round(score, 6),
                        "risk_label": "anomalous" if score > 0.92 else "normal",
                        "alerts_tail": alerts,
                    },
                )

            def do_GET(self) -> None:  # noqa: N802
                if self.path == "/health":
                    self._send_json(
                        HTTPStatus.OK,
                        {
                            "status": "ok",
                            "utc": utc_now_iso(),
                            "alerts": len(api.monitor.recent_alerts()),
                        },
                    )
                    return
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

            def log_message(self, fmt: str, *args: Any) -> None:
                # Keep demo output clean.
                return

        httpd = ThreadingHTTPServer((self.host, self.port), Handler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        return httpd

    def sign_client_request(self, body: bytes, ts: int, nonce: str) -> str:
        return hmac.new(self.hmac_secret, str(ts).encode() + nonce.encode() + body, hashlib.sha256).hexdigest()


# ----------------------------
# Demo orchestration
# ----------------------------

def create_demo_artifacts(base: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    artifacts = base / "demo_artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)

    model_path = artifacts / "vision_model.tflite"
    if not model_path.exists():
        model_path.write_bytes(os.urandom(700_000))

    metadata = {
        "model_name": "defect_detector",
        "framework": "tflite",
        "nxp_stack": "eIQ",
        "supported_soc": ["i.MX 93", "i.MX 95"],
        "note": "demo metadata",
    }
    (artifacts / "model_metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    return artifacts, model_path


def make_signed_manifest(signing_key: bytes, model_hash: str) -> dict[str, Any]:
    manifest = {
        "device_family": "i.MX 95",
        "secure_boot": True,
        "debug_firmware": False,
        "model_version": 3,
        "artifact_hash": model_hash,
        "rollout_channel": "production",
    }
    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    manifest["signature"] = hmac.new(signing_key, payload, hashlib.sha256).hexdigest()
    return manifest


def demo_client_call(api: SecureInferenceAPI, features: list[float]) -> dict[str, Any]:
    body = json.dumps({"features": features}).encode("utf-8")
    ts = int(time.time())
    nonce = base64.urlsafe_b64encode(secrets.token_bytes(8)).decode().rstrip("=")
    sig = api.sign_client_request(body, ts, nonce)

    import urllib.request

    req = urllib.request.Request(
        f"http://{api.host}:{api.port}/infer",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-API-Key": api.api_key,
            "X-Timestamp": str(ts),
            "X-Nonce": nonce,
            "X-Signature": sig,
        },
    )

    with urllib.request.urlopen(req, timeout=3) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> None:
    root = pathlib.Path(__file__).resolve().parent
    artifacts_dir, model_path = create_demo_artifacts(root)

    print("\n=== 1) Artifact Security Scan ===")
    scanner = ArtifactSecurityScanner(max_model_size_mb=5)
    report = scanner.scan(project="nxp-eiq-demo", artifacts_dir=artifacts_dir)
    print(report.to_json())

    print("\n=== 2) Deployment Workflow Gate ===")
    signing_key = secrets.token_bytes(32)
    manifest = make_signed_manifest(signing_key, sha256_file(model_path))
    guard = DeploymentWorkflowGuard(policy=DeploymentPolicy(), signing_key=signing_key)
    gate_findings = guard.verify_manifest(manifest)
    if gate_findings:
        print("Deployment blocked:")
        for f in gate_findings:
            print(dataclasses.asdict(f))
        return
    print("Deployment policy checks passed.")

    print("\n=== 3) Secure API + Runtime Monitoring ===")
    runtime = EmbeddedModelRuntime(model_path=model_path)
    monitor = ModelIntegrityMonitor(runtime=runtime)
    api = SecureInferenceAPI(host="127.0.0.1", port=8089, runtime=runtime, monitor=monitor)
    httpd = api.start()

    try:
        for i in range(20):
            # Mostly normal traffic with occasional outlier request.
            if i in (12, 17):
                vec = [random.uniform(3.0, 4.0) for _ in range(8)]
            else:
                vec = [random.uniform(0.0, 1.0) for _ in range(8)]
            result = demo_client_call(api, vec)
            print(f"call={i:02d} score={result['score']} label={result['risk_label']} alerts={len(result['alerts_tail'])}")
            time.sleep(0.05)

        print("\nRecent monitoring alerts:")
        for alert in monitor.recent_alerts()[-10:]:
            print(alert)

        print("\nDemo complete. You can inspect and extend this skeleton for real eIQ integration.")
    finally:
        httpd.shutdown()


if __name__ == "__main__":
    main()
