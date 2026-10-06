# PreviSwit AI-ASPM
# Copyright (C) 2026 PreviSwit Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""
PreviSwit — WebSocket Listener (Rádio Comunicador com a Nuvem)

Conecta-se ao servidor via WebSocket e aguarda ordens de scan.
Comandos suportados:
  - {"action": "START_SCAN",   "target": "..."}       Pipeline completo
  - {"action": "RUN_SEMGREP",  "target": "/path/..."}  SAST genérico
  - {"action": "RUN_GITLEAKS", "target": "/path/..."}  Detecção de segredos
  - {"action": "RUN_CHECKOV",  "target": "/path/..."}  Análise de IaC

Uso: python ws_listener.py
"""

import os
import sys
import json
import queue as _queue
import asyncio
import logging
from datetime import datetime, timezone

import websockets
import core.utils as _core_utils

# ─── Módulo de saúde e capacidades ────────────────────────────────────────────
from modules.system.health import get_agent_capabilities

# ─── Runners SAST individuais ───────────────────────────────────────────
from core.scanners.sast_runner import run_semgrep, run_gitleaks, run_checkov

# ─── Motor do Gêmeo Efêmero (Modo HOT) ────────────────────────────────────────
from core.ephemeral_clone import EphemeralManager, EphemeralCloneError

# ─── Configuração ───────────────────────────────────────────────────────────
WS_URI = os.getenv(
    "PREVISWIT_WS_URI",
    "wss://prevyswitserver.onrender.com/ws/agent_01",
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

# ─── Log bridge: captura print_status → WebSocket ───────────────────────────
_LEVEL_ICON = {
    "INFO":    "ℹ️",
    "SUCCESS": "✅",
    "WARN":    "⚠️",
    "ERROR":   "❌",
    "CRIT":    "🔴",
}

async def _drain_log_queue(ws, log_queue: _queue.Queue, done: asyncio.Event):
    """Drena log_queue e envia mensagens como LOG actions ao WebSocket."""
    while not done.is_set() or not log_queue.empty():
        try:
            msg = log_queue.get_nowait()
            if msg and str(msg).strip():
                await ws.send(json.dumps({"action": "LOG", "message": str(msg)}))
        except _queue.Empty:
            await asyncio.sleep(0.2)
        except Exception:
            await asyncio.sleep(0.2)


def _run_scan_blocking(target: str, pipeline: str = "all") -> tuple[dict, dict]:
    """
    Wrapper síncrono que importa e executa run_scan do main.py.
    Roda numa thread separada via asyncio.to_thread().
    """
    from main import run_scan  # noqa: import local intencional
    return run_scan(target=target, pipeline=pipeline)


async def _handle_ephemeral_scan(ws, original_target: str, pipeline: str) -> None:
    """
    Orquestra o ciclo completo do Gêmeo Efêmero (Modo HOT):
      1. spin_up()  — clona, builda e sobe o container Docker descartável
      2. Scan       — executa o pipeline apontando para a URL local do clone
      3. teardown() — SEMPRE destroi o clone, mesmo em caso de falha (try/finally)

    Envia eventos de status para o dashboard via WebSocket em cada etapa.
    """
    mgr         = EphemeralManager()
    clone_info  = None
    scan_target = original_target   # será substituído pela URL local após spin_up

    # ── 1. Notifica: construindo o Gêmeo ──────────────────────────────────────
    await ws.send(json.dumps({
        "action":  "LOG",
        "message": f"[EPHEMERAL] Iniciando construção do Gêmeo Efêmero para: {original_target}",
    }))
    await ws.send(json.dumps({
        "agent":   AGENT_ID,
        "status":  "ephemeral_building",
        "target":  original_target,
        "message": "Gêmeo Efêmero em construção...",
        "ts":      datetime.now(timezone.utc).isoformat(),
    }))

    # ── 2. spin_up() em thread (pode demorar — clone + docker build) ───────────
    try:
        clone_info = await asyncio.to_thread(mgr.spin_up, original_target)
        scan_target = clone_info["local_url"]

        log.info("[Ephemeral] Gêmeo ATIVO — %s  (clone_id=%s)", scan_target, clone_info["clone_id"])

        await ws.send(json.dumps({
            "action":  "LOG",
            "message": (
                f"[EPHEMERAL] Gêmeo Efêmero ATIVO — {scan_target} "
                f"(clone_id={clone_info['clone_id']})"
            ),
        }))
        await ws.send(json.dumps({
            "agent":    AGENT_ID,
            "status":   "ephemeral_ready",
            "clone_id": clone_info["clone_id"],
            "local_url": scan_target,
            "ts":       datetime.now(timezone.utc).isoformat(),
        }))

    except EphemeralCloneError as build_err:
        # Build falhou — não há clone para destruir (ou destruição segura foi tentada)
        log.error("[Ephemeral] Falha no spin_up: %s", build_err)
        await ws.send(json.dumps({
            "action":  "LOG",
            "message": f"[EPHEMERAL] ERRO no build do Gêmeo: {build_err}",
        }))
        await ws.send(json.dumps({
            "action": "SCAN_RESULT",
            "agent":  AGENT_ID,
            "status": "SCAN_ERROR",
            "target": original_target,
            "error":  f"Falha na criação do Gêmeo Efêmero: {build_err}",
            "ts":     datetime.now(timezone.utc).isoformat(),
        }))
        # teardown preventivo caso spin_up tenha criado recursos parciais
        if clone_info:
            await asyncio.to_thread(mgr.teardown, clone_info)
        return

    # ── 3. Executa o scan apontando para o Gêmeo — teardown GARANTIDO ─────────
    response: dict = {}
    try:
        await ws.send(json.dumps({
            "action":  "LOG",
            "message": f"[EPHEMERAL] Iniciando pipeline '{pipeline}' no Gêmeo: {scan_target}",
        }))

        # Roda o pipeline na URL local do clone (thread para não bloquear o loop)
        results, report_paths = await asyncio.to_thread(
            _run_scan_blocking, scan_target, pipeline
        )

        json_path = report_paths.get("json")
        if not json_path:
            raise FileNotFoundError("run_scan não retornou caminho do JSON.")

        def _read_json(path: str) -> dict:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)

        json_data = await asyncio.to_thread(_read_json, json_path)

        # Enriquece o resultado com metadados do clone
        json_data["_ephemeral_meta"] = {
            "clone_id":        clone_info["clone_id"],
            "original_target": original_target,
            "local_url":       scan_target,
            "mode":            "hot",
        }

        response = {
            "action": "SCAN_RESULT",
            "target": original_target,   # retorna ao frontend com o target original
            "data":   json_data,
        }
        log.info("[Ephemeral] Scan concluído — %d bytes", len(json.dumps(json_data, default=str)))

    except FileNotFoundError as fnf:
        log.error("[Ephemeral] JSON não encontrado: %s", fnf)
        response = {
            "action": "SCAN_RESULT",
            "agent":  AGENT_ID,
            "status": "SCAN_ERROR",
            "target": original_target,
            "error":  str(fnf),
            "ts":     datetime.now(timezone.utc).isoformat(),
        }
    except Exception as exc:
        log.exception("[Ephemeral] Erro inesperado no scan do Gêmeo: %s", exc)
        response = {
            "action": "SCAN_RESULT",
            "agent":  AGENT_ID,
            "status": "SCAN_ERROR",
            "target": original_target,
            "error":  str(exc),
            "ts":     datetime.now(timezone.utc).isoformat(),
        }

    finally:
        # ── TEARDOWN OBRIGATÓRIO — executa mesmo em caso de exceção ───────────
        await ws.send(json.dumps({
            "action":  "LOG",
            "message": f"[EPHEMERAL] Destruindo Gêmeo {clone_info['clone_id']}...",
        }))

        try:
            await asyncio.to_thread(mgr.teardown, clone_info)
        except Exception as td_err:
            log.warning("[Ephemeral] Falha no teardown (não crítica): %s", td_err)

        await ws.send(json.dumps({
            "agent":    AGENT_ID,
            "status":   "ephemeral_destroyed",
            "clone_id": clone_info["clone_id"],
            "message":  "Gêmeo obliterado com sucesso.",
            "ts":       datetime.now(timezone.utc).isoformat(),
        }))
        await ws.send(json.dumps({
            "action":  "LOG",
            "message": f"[EPHEMERAL] Gêmeo {clone_info['clone_id']} obliterado com sucesso.",
        }))

    # ── 4. Envia resultado ao dashboard ───────────────────────────────────────
    if response:
        await ws.send(json.dumps(response, default=str))




# ─── Handlers ───────────────────────────────────────────────────────────────

async def handle_message(ws, raw: str):
    """Processa uma mensagem JSON recebida do servidor."""
    try:
        msg = json.loads(raw)
    except json.JSONDecodeError as e:
        # ── Erro visível no terminal — NÃO morre em silêncio ──
        print(f"\n{'='*60}")
        print(f"❌ ERRO DE FORMATAÇÃO JSON!")
        print(f"   json.loads() falhou: {e}")
        print(f"   Conteúdo recebido (primeiros 300 chars):")
        print(f"   {raw[:300]}")
        print(f"{'='*60}\n")
        log.error("JSON inválido recebido do servidor: %s — raw=%s", e, raw[:200])
        return

    action = msg.get("action")
    target = msg.get("target")

    # ── START_SCAN ──────────────────────────────────────────────────────
    if action == "START_SCAN" and target:
        pipeline = msg.get("pipeline", "all")
        mode     = msg.get("mode", "safe")   # "safe" (Carga Seca) ou "hot" (Gêmeo Efêmero)

        # Aliases semânticos → pipelines numéricos aceitos por main.run_scan()
        # run_scan aceita: "1", "2", "3", "4", "6" ou "all".
        # Qualquer string fora desse conjunto faz o scan rodar 0 módulos → 0 findings.
        _PIPELINE_ALIASES = {
            # DAST rápido: Recon + Nmap + Gobuster + SSL + Subdomain + OSINT + Nikto + CORS
            # (Pipeline 1 do run_scan — cobre o essencial em ~1-2 min).
            # Não usar "all": inclui Pipelines 2/3/4/6 (crawler agressivo, IA, ataque
            # automático e Gemini attacker) e o scan passa fácil de 10 min.
            "dast_api":   "1",
            "dast":       "1",
            "recon":      "1",
            "aggressive": "2",
            "ai":         "3",
            "attack":     "4",
            "offensive":  "6",
            "full":       "all",   # opt-in explícito para o scan completo
        }
        original_pipeline = pipeline
        pipeline = _PIPELINE_ALIASES.get(pipeline, pipeline)
        if pipeline not in {"1", "2", "3", "4", "6", "all"}:
            log.warning("⚠️  Pipeline '%s' desconhecido — usando 'all' como fallback", original_pipeline)
            pipeline = "all"
        if pipeline != original_pipeline:
            log.info("🔀 Alias de pipeline: '%s' → '%s'", original_pipeline, pipeline)

        log.info("📡 ORDEM RECEBIDA  →  action=%s  target=%s  pipeline=%s  mode=%s",
                 action, target, pipeline, mode)

        # Notifica o servidor que o scan está começando
        await ws.send(json.dumps({
            "agent":  AGENT_ID,
            "status": "scanning",
            "target": target,
            "ts":     datetime.now(timezone.utc).isoformat(),
        }))

        # ── Modo HOT: Gêmeo Efêmero ──────────────────────────────────────
        if mode == "hot":
            await _handle_ephemeral_scan(ws, target, pipeline)
            return

        # ── Modo SAFE: Scan direto no alvo ───────────────────────────────
        response   = {}
        log_queue  = _queue.Queue()
        done_event = asyncio.Event()
        _orig_ps   = _core_utils.print_status
        drain_task = None

        def _ws_print_status(msg, level="INFO"):
            _orig_ps(msg, level)
            text = str(msg).strip()
            if text:
                icon = _LEVEL_ICON.get(level, "")
                log_queue.put(f"{icon} {text}" if icon else text)

        _core_utils.print_status = _ws_print_status
        drain_task = asyncio.ensure_future(
            _drain_log_queue(ws, log_queue, done_event)
        )

        try:

            # Roda o pipeline inteiro em thread separada para não
            # bloquear o event-loop e manter o WebSocket vivo.
            results, report_paths = await asyncio.to_thread(
                _run_scan_blocking, target, pipeline
            )

            # ── Lê o arquivo JSON gerado pelo run_scan ──────────────
            json_path = report_paths.get("json")

            if not json_path:
                raise FileNotFoundError(
                    "run_scan não retornou o caminho do relatório JSON em report_paths"
                )

            log.info("📂 Lendo relatório JSON: %s", json_path)

            # Leitura síncrona em thread para não bloquear o loop
            def _read_json(path: str) -> dict:
                with open(path, "r", encoding="utf-8") as fh:
                    return json.load(fh)

            json_data = await asyncio.to_thread(_read_json, json_path)

            # Payload final com o conteúdo completo do JSON
            response = {
                "action": "SCAN_RESULT",
                "target": target,
                "data":   json_data,
            }

            log.info("✅ SCAN CONCLUÍDO — JSON lido com sucesso (%d bytes)",
                     len(json.dumps(json_data, default=str)))

        except FileNotFoundError as fnf:
            log.error("📁 Arquivo JSON não encontrado: %s", fnf)
            response = {
                "action": "SCAN_RESULT",
                "agent":  AGENT_ID,
                "status": "SCAN_ERROR",
                "target": target,
                "error":  f"Arquivo JSON não encontrado: {fnf}",
                "ts":     datetime.now(timezone.utc).isoformat(),
            }

        except (json.JSONDecodeError, OSError) as read_err:
            log.error("❌ Erro ao ler/decodificar o JSON: %s", read_err)
            response = {
                "action": "SCAN_RESULT",
                "agent":  AGENT_ID,
                "status": "SCAN_ERROR",
                "target": target,
                "error":  f"Erro ao ler relatório JSON: {read_err}",
                "ts":     datetime.now(timezone.utc).isoformat(),
            }

        except Exception as exc:
            log.exception("Erro durante o scan de %s", target)
            response = {
                "action": "SCAN_RESULT",
                "agent":  AGENT_ID,
                "status": "SCAN_ERROR",
                "target": target,
                "error":  str(exc),
                "ts":     datetime.now(timezone.utc).isoformat(),
            }

        finally:
            # ── Encerra o patch e drena mensagens restantes ───────────────
            _core_utils.print_status = _orig_ps
            done_event.set()
            if drain_task is not None:
                try:
                    await asyncio.wait_for(drain_task, timeout=2.0)
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    drain_task.cancel()

        await ws.send(json.dumps(response, default=str))

    # ── RUN_SEMGREP ───────────────────────────────────────────────
    elif action == "RUN_SEMGREP" and target:
        log.info("💿 [SAST] Semgrep solicitado para: %s", target)
        await ws.send(json.dumps({"agent": AGENT_ID, "action": "SCAN_STARTED", "tool": "semgrep", "target": target}))
        try:
            data = await run_semgrep(target)
        except Exception as exc:
            log.exception("Erro inesperado no handler RUN_SEMGREP")
            data = {"status": "error", "tool": "semgrep", "reason": str(exc)}
        await ws.send(json.dumps({
            "action": "SCAN_RESULT",
            "agent":  AGENT_ID,
            "tool":   "semgrep",
            "target": target,
            "data":   data,
            "ts":     datetime.now(timezone.utc).isoformat(),
        }, default=str))

    # ── RUN_GITLEAKS ──────────────────────────────────────────────
    elif action == "RUN_GITLEAKS" and target:
        log.info("🔑 [SAST] Gitleaks solicitado para: %s", target)
        await ws.send(json.dumps({"agent": AGENT_ID, "action": "SCAN_STARTED", "tool": "gitleaks", "target": target}))
        try:
            data = await run_gitleaks(target)
        except Exception as exc:
            log.exception("Erro inesperado no handler RUN_GITLEAKS")
            data = {"status": "error", "tool": "gitleaks", "reason": str(exc)}
        await ws.send(json.dumps({
            "action": "SCAN_RESULT",
            "agent":  AGENT_ID,
            "tool":   "gitleaks",
            "target": target,
            "data":   data,
            "ts":     datetime.now(timezone.utc).isoformat(),
        }, default=str))

    # ── RUN_CHECKOV ──────────────────────────────────────────────
    elif action == "RUN_CHECKOV" and target:
        log.info("🏗️  [SAST] Checkov solicitado para: %s", target)
        await ws.send(json.dumps({"agent": AGENT_ID, "action": "SCAN_STARTED", "tool": "checkov", "target": target}))
        try:
            data = await run_checkov(target)
        except Exception as exc:
            log.exception("Erro inesperado no handler RUN_CHECKOV")
            data = {"status": "error", "tool": "checkov", "reason": str(exc)}
        await ws.send(json.dumps({
            "action": "SCAN_RESULT",
            "agent":  AGENT_ID,
            "tool":   "checkov",
            "target": target,
            "data":   data,
            "ts":     datetime.now(timezone.utc).isoformat(),
        }, default=str))

    # ── PING / outros ──────────────────────────────────────────────
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

                # ── Handshake: anuncia presença ─────────────────────────────
                await ws.send(json.dumps({
                    "agent":  AGENT_ID,
                    "status": "online",
                    "ts":     datetime.now(timezone.utc).isoformat(),
                }))

                # ── Dynamic Tool Discovery: reporta capacidades reais ───────
                # Executa em thread para não bloquear o event-loop durante
                # chamadas de subprocess (verificação de versões dos binários)
                log.info("📡 Coletando capabilities do agente…")
                try:
                    caps = await asyncio.to_thread(get_agent_capabilities)
                    await ws.send(json.dumps({
                        "action": "AGENT_CAPABILITIES",
                        "agent":  AGENT_ID,
                        "data":   caps,
                    }))
                    active_tools = caps.get("summary", {}).get("active_tools", "?")
                    active_apis  = caps.get("summary", {}).get("active_apis", "?")
                    log.info(
                        "✅ AGENT_CAPABILITIES enviado — %s ferramentas ativas, %s APIs configuradas",
                        active_tools, active_apis,
                    )
                except Exception as caps_err:
                    log.warning("⚠️  Falha ao coletar capabilities: %s", caps_err)

                # ── Loop de escuta de comandos ──────────────────────────────
                async for raw_msg in ws:
                    # ── DEBUG: mostra exatamente o que chegou do servidor ──
                    print(f"\n[RECEBIDO DA NUVEM]: {raw_msg}")
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

