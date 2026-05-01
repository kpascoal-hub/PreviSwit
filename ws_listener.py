"""
PreviSwit — WebSocket Listener (Rádio Comunicador com a Nuvem)

Conecta-se ao servidor Render via WebSocket e aguarda ordens de scan.
Quando recebe {"action": "START_SCAN", "target": "URL"}, executa o pipeline
completo e devolve o resultado + caminhos dos relatórios.

Uso: python ws_listener.py
"""

import os
import sys
import json
import asyncio
import logging
from datetime import datetime, timezone

import websockets

# ─── Configuração ───────────────────────────────────────────────────────────
WS_URI = os.getenv(
    "PREVISWIT_WS_URI",
    "wss:https://prevyswitserver.onrender.com/",
)

AGENT_ID        = os.getenv("PREVISWIT_AGENT_ID", "agent_01")
RETRY_BASE      = 5        # segundos — base para reconexão
RETRY_MAX       = 60       # segundos — teto para backoff exponencial
HEARTBEAT_SEC   = 30       # ping keepalive

# ─── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("ws_listener")

# ─── Import do pipeline (lazy) ─────────────────────────────────────────────
# O import é feito dentro da função para evitar efeitos colaterais ao
# carregar o módulo (ex: colorama.init, argparse, etc.).


def _run_scan_blocking(target: str, pipeline: str = "all") -> tuple[dict, dict]:
    """
    Wrapper síncrono que importa e executa run_scan do main.py.
    Roda numa thread separada via asyncio.to_thread().
    """
    from main import run_scan  # noqa: import local intencional
    return run_scan(target=target, pipeline=pipeline)


# ─── Handlers ───────────────────────────────────────────────────────────────

async def handle_message(ws, raw: str):
    """Processa uma mensagem JSON recebida do servidor."""
    try:
        msg = json.loads(raw)
    except json.JSONDecodeError:
        log.warning("Mensagem recebida não é JSON válido: %s", raw[:200])
        return

    action = msg.get("action")
    target = msg.get("target")

    # ── START_SCAN ──────────────────────────────────────────────────────
    if action == "START_SCAN" and target:
        pipeline = msg.get("pipeline", "all")
        log.info("📡 ORDEM RECEBIDA  →  action=%s  target=%s  pipeline=%s",
                 action, target, pipeline)

        # Notifica o servidor que o scan está começando
        await ws.send(json.dumps({
            "agent":  AGENT_ID,
            "status": "scanning",
            "target": target,
            "ts":     datetime.now(timezone.utc).isoformat(),
        }))

        try:
            # Roda o pipeline inteiro em thread separada para não
            # bloquear o event-loop e manter o WebSocket vivo.
            results, report_paths = await asyncio.to_thread(
                _run_scan_blocking, target, pipeline
            )

            # Monta resumo compacto para enviar de volta
            findings  = results.get("findings_prioritized", [])
            total     = len(findings)
            critical  = sum(1 for f in findings if f.get("severity", "").upper() == "CRITICAL")
            high      = sum(1 for f in findings if f.get("severity", "").upper() == "HIGH")

            response = {
                "agent":    AGENT_ID,
                "status":   "SCAN_COMPLETE",
                "target":   target,
                "summary": {
                    "total_findings": total,
                    "critical":       critical,
                    "high":           high,
                },
                "report_paths": report_paths,
                "ai_insights":  results.get("ai_insights", [])[:5],
                "ts":           datetime.now(timezone.utc).isoformat(),
            }

            log.info("✅ SCAN CONCLUÍDO  →  %d findings (%d crit, %d high)",
                     total, critical, high)

        except Exception as exc:
            log.exception("Erro durante o scan de %s", target)
            response = {
                "agent":  AGENT_ID,
                "status": "SCAN_ERROR",
                "target": target,
                "error":  str(exc),
                "ts":     datetime.now(timezone.utc).isoformat(),
            }

        await ws.send(json.dumps(response, default=str))

    # ── PING / outros ──────────────────────────────────────────────────
    elif action == "PING":
        await ws.send(json.dumps({"agent": AGENT_ID, "action": "PONG"}))
    else:
        log.debug("Mensagem ignorada: %s", raw[:200])


# ─── Loop principal com reconexão automática ────────────────────────────────

async def listen_forever():
    """Conecta ao servidor e fica em loop infinito com reconexão automática."""
    retry_delay = RETRY_BASE

    while True:
        try:
            log.info("🔌 Conectando a %s …", WS_URI)

            async with websockets.connect(
                WS_URI,
                ping_interval=HEARTBEAT_SEC,
                ping_timeout=HEARTBEAT_SEC * 2,
                close_timeout=10,
            ) as ws:
                log.info("🟢 Conectado ao servidor!")
                retry_delay = RETRY_BASE  # reset após conexão bem-sucedida

                # Anuncia presença
                await ws.send(json.dumps({
                    "agent":  AGENT_ID,
                    "status": "online",
                    "ts":     datetime.now(timezone.utc).isoformat(),
                }))

                # Loop de escuta
                async for raw_msg in ws:
                    await handle_message(ws, raw_msg)

        except (
            websockets.ConnectionClosedError,
            websockets.ConnectionClosedOK,
        ) as e:
            log.warning("🔴 Conexão encerrada: %s", e)

        except (
            ConnectionRefusedError,
            OSError,
            asyncio.TimeoutError,
        ) as e:
            log.warning("🔴 Falha de conexão: %s", e)

        except Exception as e:
            log.exception("🔴 Erro inesperado: %s", e)

        # ── Backoff exponencial ────────────────────────────────────────
        log.info("🔄 Reconectando em %d segundos…", retry_delay)
        await asyncio.sleep(retry_delay)
        retry_delay = min(retry_delay * 2, RETRY_MAX)


# ─── Entrypoint ─────────────────────────────────────────────────────────────

def main():
    log.info("═══════════════════════════════════════════════════════")
    log.info("  PreviSwit — WebSocket Listener v1.0")
    log.info("  Servidor: %s", WS_URI)
    log.info("  Agent ID: %s", AGENT_ID)
    log.info("═══════════════════════════════════════════════════════")

    try:
        asyncio.run(listen_forever())
    except KeyboardInterrupt:
        log.info("⏹  Listener encerrado pelo usuário.")
        sys.exit(0)


if __name__ == "__main__":
    main()
