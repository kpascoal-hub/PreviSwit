"""
core/ws_client.py
WebSocket client that connects to the ASPM backend and orchestrates
the full autonomous scan → filter → AI validation pipeline on demand.
"""

import asyncio
import json
import logging
import os

import websockets
from dotenv import load_dotenv
from websockets.exceptions import ConnectionClosedError, ConnectionClosedOK

load_dotenv()

# --- Scanner imports ---
from core.scanners.nmap_runner import run_nmap
from core.scanners.nuclei_runner import run_nuclei
from core.scanners.trivy_runner import run_trivy

# --- AI import ---
from core.ai_offensive.ai_engine import validate_vuln

logger = logging.getLogger(__name__)

WS_URL: str = os.getenv("WS_SERVER_URL", "ws://localhost:8000/ws/agent_01")
RECONNECT_DELAY: int = int(os.getenv("WS_RECONNECT_DELAY", "5"))

# Severities that are actionable — everything else is discarded as noise
_CRITICAL_SEVERITIES: frozenset[str] = frozenset({"high", "critical"})


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _filter_noise(findings: list[dict]) -> list[dict]:
    """
    Discard any finding whose severity is not 'high' or 'critical'.
    The severity field is normalised to lowercase before comparison.
    """
    return [
        f for f in findings
        if str(f.get("severity", "")).lower() in _CRITICAL_SEVERITIES
    ]


# ---------------------------------------------------------------------------
# WebSocket agent
# ---------------------------------------------------------------------------

class AgentWebSocket:
    """
    Persistent WebSocket agent that listens for control commands
    and orchestrates the full autonomous scan pipeline.

    Supported incoming message actions:
        START_SCAN  — runs nmap + nuclei + trivy against 'target',
                      filters noise (High/Critical only), validates
                      each critical finding with the AI engine, and
                      sends a structured report back.
        PING        — responds with PONG (health-check).
    """

    def __init__(self, url: str = WS_URL) -> None:
        self.url = url
        self._ws: websockets.WebSocketClientProtocol | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """
        Connect to the WebSocket server and enter the message loop.
        Automatically retries on disconnection.
        """
        while True:
            try:
                logger.info("Connecting to %s …", self.url)
                async with websockets.connect(self.url) as ws:
                    self._ws = ws
                    logger.info("Connected to %s", self.url)
                    await self._message_loop(ws)

            except (ConnectionRefusedError, OSError):
                logger.warning(
                    "WebSocket server not reachable at %s. Retrying in %ds …",
                    self.url,
                    RECONNECT_DELAY,
                )
            except (ConnectionClosedOK, ConnectionClosedError) as exc:
                logger.warning("Connection closed (%s). Reconnecting in %ds …", exc, RECONNECT_DELAY)
            except Exception as exc:  # noqa: BLE001
                logger.exception("Unexpected error in WebSocket loop: %s", exc)

            finally:
                self._ws = None
                await asyncio.sleep(RECONNECT_DELAY)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _message_loop(self, ws: websockets.WebSocketClientProtocol) -> None:
        """Continuously receive and dispatch messages."""
        async for raw_message in ws:
            await self._handle_message(ws, raw_message)

    async def _handle_message(
        self,
        ws: websockets.WebSocketClientProtocol,
        raw_message: str,
    ) -> None:
        """Parse a raw WebSocket message and dispatch to the right handler."""
        try:
            message: dict = json.loads(raw_message)
        except json.JSONDecodeError:
            logger.warning("Received non-JSON message: %r", raw_message)
            return

        action = message.get("action", "").upper()
        logger.info("Received action: %s", action)

        if action == "START_SCAN":
            target = message.get("target", "").strip()
            if not target:
                await self._send(ws, {"error": "START_SCAN requires a 'target' field."})
                return
            await self._run_full_pipeline(ws, target)

        elif action == "PING":
            await self._send(ws, {"action": "PONG", "agent": "agent_01"})

        else:
            logger.warning("Unknown action received: '%s'", action)
            await self._send(ws, {"error": f"Unknown action: {action}"})

    async def _run_full_pipeline(
        self,
        ws: websockets.WebSocketClientProtocol,
        target: str,
    ) -> None:
        """
        Autonomous scan pipeline:

            Phase 1 — SCANNING
                Run nmap, nuclei, and trivy in parallel via asyncio.gather
                using asyncio.to_thread() so that blocking subprocess calls
                never stall the event loop.

            Phase 2 — FILTERING
                Discard any finding whose severity is not 'high' or 'critical'.

            Phase 3 — AI ANALYSIS
                For each critical finding, call validate_vuln() from ai_engine
                also via asyncio.to_thread() (requests is blocking).
                Errors per finding are caught individually so one failure does
                not block the rest.

            Phase 4 — REPORT
                Send a single structured JSON report with raw findings,
                filtered findings, AI-generated attack payloads and fix code.

        Real-time status messages are sent to the server after each phase.
        """

        # ── Phase 1: SCANNING ──────────────────────────────────────────────
        logger.info("[Pipeline] Phase 1 — SCANNING target: %s", target)
        await self._send(ws, {"status": "scanning", "target": target})

        # Nuclei expects a full URL; ensure http:// prefix when not present
        nuclei_target = target if target.startswith("http") else f"http://{target}"
        # Trivy scans the local filesystem — pass "." (project root) instead of a web URL
        nmap_result, nuclei_result, trivy_result = await asyncio.gather(
            asyncio.to_thread(run_nmap, target),
            asyncio.to_thread(run_nuclei, nuclei_target),
            asyncio.to_thread(run_trivy, "."),
            return_exceptions=True,          # never raise — capture errors
        )

        # Unwrap exceptions from individual scanners without aborting pipeline
        def _safe_result(res, scanner_name: str) -> dict:
            if isinstance(res, Exception):
                logger.error("[Pipeline] %s raised: %s", scanner_name, res)
                return {
                    "source": scanner_name,
                    "mock": True,
                    "status": "error",
                    "findings": [],
                    "message": str(res),
                }
            return res

        nmap_result    = _safe_result(nmap_result,   "nmap")
        nuclei_result  = _safe_result(nuclei_result, "nuclei")
        trivy_result   = _safe_result(trivy_result,  "trivy")

        # Collect all findings that carry a structured list (nmap included)
        raw_findings: list[dict] = []
        for scanner_result in (nmap_result, nuclei_result, trivy_result):
            raw_findings.extend(scanner_result.get("findings", []))

        logger.info("[Pipeline] Raw findings: %d", len(raw_findings))

        # ── Phase 2: FILTERING ─────────────────────────────────────────────
        logger.info("[Pipeline] Phase 2 — FILTERING (High/Critical only)")
        await self._send(ws, {"status": "filtering_data", "raw_count": len(raw_findings)})

        filtered_findings = _filter_noise(raw_findings)
        logger.info(
            "[Pipeline] Filtered findings: %d (discarded: %d)",
            len(filtered_findings),
            len(raw_findings) - len(filtered_findings),
        )

        # ── Phase 3: AI ANALYSIS ───────────────────────────────────────────
        logger.info("[Pipeline] Phase 3 — AI ANALYSIS (%d finding(s))", len(filtered_findings))
        await self._send(
            ws,
            {
                "status": "ai_analysis",
                "critical_count": len(filtered_findings),
            },
        )

        attack_payloads: list[dict] = []
        fix_codes: list[dict] = []

        for finding in filtered_findings:
            vuln_id = (
                finding.get("vulnerability_id")
                or finding.get("template_id")
                or finding.get("name", "unknown")
            )
            logger.info("[Pipeline] Sending finding '%s' to AI…", vuln_id)

            try:
                ai_result: dict = await asyncio.to_thread(validate_vuln, finding)

                attack_payloads.append(
                    {
                        "vulnerability_id": vuln_id,
                        "severity": finding.get("severity", ""),
                        "payload_teste": ai_result.get("payload_teste", ""),
                        "ai_mock": ai_result.get("mock", False),
                    }
                )
                fix_codes.append(
                    {
                        "vulnerability_id": vuln_id,
                        "severity": finding.get("severity", ""),
                        "codigo_correcao": ai_result.get("codigo_correcao", ""),
                        "ai_mock": ai_result.get("mock", False),
                    }
                )

            except Exception as exc:  # noqa: BLE001
                logger.error("[Pipeline] AI analysis failed for '%s': %s", vuln_id, exc)
                attack_payloads.append(
                    {
                        "vulnerability_id": vuln_id,
                        "severity": finding.get("severity", ""),
                        "payload_teste": "",
                        "ai_mock": True,
                        "error": str(exc),
                    }
                )
                fix_codes.append(
                    {
                        "vulnerability_id": vuln_id,
                        "severity": finding.get("severity", ""),
                        "codigo_correcao": "",
                        "ai_mock": True,
                        "error": str(exc),
                    }
                )

        # ── Phase 4: FINAL REPORT ──────────────────────────────────────────
        logger.info("[Pipeline] Phase 4 — REPORT for target: %s", target)

        report = {
            "status": "SCAN_COMPLETE",
            "target": target,
            # Structured scanner results
            "scanners": {
                "nmap": nmap_result,
                "nuclei": nuclei_result,
                "trivy": trivy_result,
            },
            # Raw findings from Nuclei + Trivy (before filtering)
            "raw_findings": raw_findings,
            "total_raw": len(raw_findings),
            # Findings after High/Critical filter
            "filtered_findings": filtered_findings,
            "total_filtered": len(filtered_findings),
            # AI-generated payloads per finding
            "attack_payloads": attack_payloads,
            # AI-generated remediation code per finding
            "fix_codes": fix_codes,
        }

        await self._send(ws, report)
        logger.info("[Pipeline] ✅ Complete for target: %s", target)

    @staticmethod
    async def _send(ws: websockets.WebSocketClientProtocol, data: dict) -> None:
        """Serialize and send a dict as JSON over the WebSocket."""
        try:
            await ws.send(json.dumps(data, default=str))
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to send WebSocket message: %s", exc)
