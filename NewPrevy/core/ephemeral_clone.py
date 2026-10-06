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
PreviSwit AI-ASPM — core/ephemeral_clone.py
Gêmeo Efêmero (Digital Twin): clonagem e destruição de ambientes Docker descartáveis.

Responsabilidades:
  - Clonar repositórios Git (ou usar caminhos locais) em diretórios temporários isolados.
  - Detectar o mecanismo de container: docker-compose.yml/yaml → Compose; Dockerfile → build simples.
  - Subir o container em modo detached e identificar a porta exposta dinamicamente.
  - Garantir a destruição SEMPRE (via try/finally no chamador) mesmo em caso de falha de build.

Princípios de Resiliência:
  - Nunca usa APIs de cloud — apenas a CLI do Docker local.
  - Todos os subprocessos têm timeout configurável para evitar travar o event-loop.
  - teardown() nunca levanta exceção — falhas são logadas e engolidas para garantir o descarte.
  - Toda pasta temporária é prefixada com 'previswit_twin_' + UUID para evitar conflitos.

Uso típico (dentro do ws_listener.py):
    mgr = EphemeralManager()
    clone = mgr.spin_up(repo_url_or_path)
    try:
        scan(clone["local_url"])
    finally:
        mgr.teardown(clone)
"""

import json
import logging
import os
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from typing import Optional

log = logging.getLogger("ephemeral_clone")

# ── Constantes ────────────────────────────────────────────────────────────────

# Pasta-raiz onde todos os clones serão criados
_TWINS_ROOT = Path(os.getenv("PREVISWIT_TWINS_DIR", "/tmp/previswit_twins"))

# Timeout para git clone e docker build/up (segundos)
_CLONE_TIMEOUT     = 120   # 2 min para clone git
_BUILD_TIMEOUT     = 300   # 5 min para docker build
_PORT_WAIT_TIMEOUT = 30    # aguarda o container expor a porta
_PORT_WAIT_INTERVAL = 1    # intervalo de verificação de porta (segundos)

# Portas de partida para detecção de binding
_PORT_SCAN_START = 8100
_PORT_SCAN_END   = 8999


class EphemeralCloneError(RuntimeError):
    """Erro controlado do ciclo de vida do Gêmeo Efêmero."""


class EphemeralManager:
    """
    Gerencia o ciclo de vida completo de um Gêmeo Efêmero:
      spin_up()  → clona, builda e sobe o container
      teardown() → derruba e apaga tudo, sem exceções
    """

    def __init__(self):
        _TWINS_ROOT.mkdir(parents=True, exist_ok=True)
        log.info("[EphemeralManager] Diretório de twins: %s", _TWINS_ROOT)

    # ── Spin Up ───────────────────────────────────────────────────────────────

    def spin_up(self, repo_url_or_path: str) -> dict:
        """
        Clona (ou copia) o alvo, detecta o tipo de container e sobe o Gêmeo Efêmero.

        Args:
            repo_url_or_path: URL Git (https://...) ou caminho local de um projeto.

        Returns:
            {
                "clone_id":  str  — identificador único do clone (prefixo dos recursos Docker),
                "local_url": str  — URL local onde o Gêmeo está servindo (http://localhost:PORT),
                "temp_dir":  str  — caminho absoluto da pasta temporária,
                "port":      int  — porta local bindada,
                "compose":   bool — True se foi usado docker-compose; False se Dockerfile simples,
            }

        Raises:
            EphemeralCloneError se qualquer etapa crítica falhar.
        """
        clone_id  = "twin_" + uuid.uuid4().hex[:10]
        temp_dir  = _TWINS_ROOT / clone_id

        log.info("[Spin Up] clone_id=%s  alvo=%s", clone_id, repo_url_or_path)

        # ── 1. Obter o código ──────────────────────────────────────────────
        temp_dir = self._acquire_source(repo_url_or_path, temp_dir, clone_id)

        # ── 2. Detectar mecanismo de container ────────────────────────────
        compose_file = self._find_compose_file(temp_dir)
        dockerfile   = temp_dir / "Dockerfile"

        if not compose_file and not dockerfile.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise EphemeralCloneError(
                f"Nenhum docker-compose.yml nem Dockerfile encontrado em {temp_dir}"
            )

        use_compose = compose_file is not None
        log.info("[Spin Up] Mecanismo: %s", "docker-compose" if use_compose else "Dockerfile")

        # ── 3. Build e Up ─────────────────────────────────────────────────
        port = self._build_and_run(temp_dir, clone_id, compose_file, use_compose)

        local_url = f"http://localhost:{port}"
        log.info("[Spin Up] Gêmeo Efêmero ATIVO — %s  (clone_id=%s)", local_url, clone_id)

        return {
            "clone_id":  clone_id,
            "local_url": local_url,
            "temp_dir":  str(temp_dir),
            "port":      port,
            "compose":   use_compose,
        }

    # ── Teardown ──────────────────────────────────────────────────────────────

    def teardown(self, clone_info: dict) -> None:
        """
        Derruba e apaga completamente o Gêmeo Efêmero.
        NUNCA levanta exceção — qualquer falha é logada e engolida.

        Args:
            clone_info: dicionário retornado por spin_up().
        """
        clone_id = clone_info.get("clone_id", "?")
        temp_dir = clone_info.get("temp_dir", "")
        use_compose = clone_info.get("compose", False)

        log.info("[Teardown] Destruindo clone_id=%s", clone_id)

        # ── 1. Derrubar containers ─────────────────────────────────────────
        try:
            if use_compose and temp_dir and Path(temp_dir).exists():
                self._compose_down(temp_dir)
            else:
                self._docker_rm(clone_id)
        except Exception as e:
            log.warning("[Teardown] Falha ao derrubar containers (ignorada): %s", e)

        # ── 2. Remover imagens criadas ─────────────────────────────────────
        try:
            self._remove_images(clone_id)
        except Exception as e:
            log.warning("[Teardown] Falha ao remover imagens (ignorada): %s", e)

        # ── 3. Apagar pasta temporária ─────────────────────────────────────
        try:
            if temp_dir and Path(temp_dir).exists():
                shutil.rmtree(temp_dir, ignore_errors=True)
                log.info("[Teardown] Pasta removida: %s", temp_dir)
        except Exception as e:
            log.warning("[Teardown] Falha ao remover pasta (ignorada): %s", e)

        log.info("[Teardown] Clone %s obliterado com sucesso.", clone_id)

    # ── Métodos Internos ──────────────────────────────────────────────────────

    def _acquire_source(self, source: str, temp_dir: Path, clone_id: str) -> Path:
        """Clona via Git ou copia pasta local para temp_dir."""
        is_git = source.startswith("http://") or source.startswith("https://") or source.startswith("git@")

        if is_git:
            log.info("[Spin Up] Clonando repositório: %s → %s", source, temp_dir)
            try:
                result = subprocess.run(
                    ["git", "clone", "--depth=1", "--quiet", source, str(temp_dir)],
                    capture_output=True, text=True, timeout=_CLONE_TIMEOUT,
                )
                if result.returncode != 0:
                    raise EphemeralCloneError(
                        f"git clone falhou (code {result.returncode}): {result.stderr[:400]}"
                    )
            except FileNotFoundError:
                raise EphemeralCloneError("Binário 'git' não encontrado no PATH.")
            except subprocess.TimeoutExpired:
                raise EphemeralCloneError(f"git clone excedeu {_CLONE_TIMEOUT}s. Repositório muito grande?")
        else:
            # Caminho local — copia a árvore
            source_path = Path(source)
            if not source_path.exists():
                raise EphemeralCloneError(f"Caminho local não encontrado: {source}")
            log.info("[Spin Up] Copiando fonte local: %s → %s", source_path, temp_dir)
            shutil.copytree(source_path, temp_dir)

        return temp_dir

    def _find_compose_file(self, directory: Path) -> Optional[Path]:
        """Retorna o caminho do docker-compose se existir, senão None."""
        for name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
            p = directory / name
            if p.exists():
                return p
        return None

    def _build_and_run(
        self,
        temp_dir: Path,
        clone_id: str,
        compose_file: Optional[Path],
        use_compose: bool,
    ) -> int:
        """Realiza o build e up do container, retorna a porta local bindada."""
        if use_compose:
            return self._compose_up(temp_dir, clone_id, compose_file)
        else:
            return self._dockerfile_run(temp_dir, clone_id)

    def _compose_up(self, temp_dir: Path, clone_id: str, compose_file: Path) -> int:
        """Sobe via docker compose, detecta e retorna a porta exposta."""
        log.info("[Spin Up] docker compose up -d  (projeto: %s)", clone_id)

        # Injeta COMPOSE_PROJECT_NAME via env para isolar completamente o projeto
        env = {**os.environ, "COMPOSE_PROJECT_NAME": clone_id}

        try:
            result = subprocess.run(
                ["docker", "compose", "-f", str(compose_file), "up", "--build", "-d"],
                capture_output=True, text=True, timeout=_BUILD_TIMEOUT, cwd=str(temp_dir), env=env,
            )
            if result.returncode != 0:
                raise EphemeralCloneError(
                    f"docker compose up falhou (code {result.returncode}):\n{result.stderr[:600]}"
                )
        except FileNotFoundError:
            raise EphemeralCloneError("Docker não encontrado no PATH. Verifique a instalação.")
        except subprocess.TimeoutExpired:
            raise EphemeralCloneError(f"docker compose up excedeu {_BUILD_TIMEOUT}s.")

        # Detecta porta exposta via `docker compose port`
        port = self._detect_port_compose(temp_dir, clone_id, compose_file)
        return port

    def _dockerfile_run(self, temp_dir: Path, clone_id: str) -> int:
        """Build de Dockerfile simples + docker run, retorna a porta alocada."""
        image_tag = f"previswit/{clone_id}:ephemeral"
        log.info("[Spin Up] docker build  tag=%s", image_tag)

        try:
            build = subprocess.run(
                ["docker", "build", "-t", image_tag, "."],
                capture_output=True, text=True, timeout=_BUILD_TIMEOUT, cwd=str(temp_dir),
            )
            if build.returncode != 0:
                raise EphemeralCloneError(
                    f"docker build falhou (code {build.returncode}):\n{build.stderr[:600]}"
                )
        except FileNotFoundError:
            raise EphemeralCloneError("Docker não encontrado no PATH.")
        except subprocess.TimeoutExpired:
            raise EphemeralCloneError(f"docker build excedeu {_BUILD_TIMEOUT}s.")

        # Descobre porta exposta no Dockerfile (EXPOSE)
        exposed_port = self._parse_exposed_port(temp_dir / "Dockerfile") or 8080

        # Usa porta aleatória no host (0 = SO aloca)
        log.info("[Spin Up] docker run (expose %d) — container=%s", exposed_port, clone_id)
        try:
            run_result = subprocess.run(
                [
                    "docker", "run", "-d",
                    "--name", clone_id,
                    "-p", f"0:{exposed_port}",   # host porta aleatória
                    image_tag,
                ],
                capture_output=True, text=True, timeout=30,
            )
            if run_result.returncode != 0:
                raise EphemeralCloneError(
                    f"docker run falhou (code {run_result.returncode}): {run_result.stderr[:400]}"
                )
        except subprocess.TimeoutExpired:
            raise EphemeralCloneError("docker run excedeu 30s.")

        # Resolve a porta alocada pelo SO
        port = self._resolve_host_port(clone_id, exposed_port)
        return port

    def _detect_port_compose(
        self, temp_dir: Path, clone_id: str, compose_file: Path, retries: int = 10
    ) -> int:
        """
        Usa `docker compose port` para descobrir o binding de porta.
        Aguarda o container estar running com retries.
        """
        env = {**os.environ, "COMPOSE_PROJECT_NAME": clone_id}

        for attempt in range(retries):
            try:
                port_result = subprocess.run(
                    ["docker", "compose", "-f", str(compose_file), "port",
                     self._first_service_name(compose_file), "80"],
                    capture_output=True, text=True, timeout=10,
                    cwd=str(temp_dir), env=env,
                )
                if port_result.returncode == 0 and ":" in port_result.stdout:
                    host_port = int(port_result.stdout.strip().split(":")[-1])
                    log.info("[Spin Up] Porta detectada via compose port: %d", host_port)
                    return host_port
            except Exception:
                pass
            time.sleep(_PORT_WAIT_INTERVAL)

        # Fallback: tenta detectar via docker ps
        return self._detect_port_via_ps(clone_id)

    def _resolve_host_port(self, container_name: str, container_port: int) -> int:
        """Descobre a porta host de um container via `docker port`."""
        for _ in range(_PORT_WAIT_TIMEOUT):
            try:
                r = subprocess.run(
                    ["docker", "port", container_name, str(container_port)],
                    capture_output=True, text=True, timeout=5,
                )
                if r.returncode == 0 and ":" in r.stdout:
                    return int(r.stdout.strip().split(":")[-1])
            except Exception:
                pass
            time.sleep(_PORT_WAIT_INTERVAL)
        raise EphemeralCloneError(f"Não foi possível detectar a porta do container '{container_name}'.")

    def _detect_port_via_ps(self, clone_id: str) -> int:
        """Fallback: parseia `docker ps` procurando containers do clone."""
        try:
            ps = subprocess.run(
                ["docker", "ps", "--filter", f"name={clone_id}", "--format", "{{.Ports}}"],
                capture_output=True, text=True, timeout=10,
            )
            # Formato: "0.0.0.0:8243->80/tcp"
            match = re.search(r":(\d+)->", ps.stdout)
            if match:
                return int(match.group(1))
        except Exception:
            pass
        raise EphemeralCloneError(f"Porta não detectada para clone {clone_id} via docker ps.")

    def _first_service_name(self, compose_file: Path) -> str:
        """Extrai o nome do primeiro serviço do docker-compose.yml (sem yaml lib)."""
        try:
            with open(compose_file, "r", encoding="utf-8") as f:
                for line in f:
                    stripped = line.rstrip()
                    # Primeira linha indentada com 2 espaços sob 'services:'
                    if re.match(r"^  \w", stripped) and ":" in stripped:
                        name = stripped.strip().rstrip(":")
                        if name not in ("version", "volumes", "networks"):
                            return name
        except Exception:
            pass
        return "app"  # fallback genérico

    def _parse_exposed_port(self, dockerfile: Path) -> Optional[int]:
        """Extrai o primeiro EXPOSE do Dockerfile."""
        try:
            with open(dockerfile, "r", encoding="utf-8") as f:
                for line in f:
                    m = re.match(r"^\s*EXPOSE\s+(\d+)", line, re.IGNORECASE)
                    if m:
                        return int(m.group(1))
        except Exception:
            pass
        return None

    def _compose_down(self, temp_dir: str) -> None:
        """docker compose down -v para remover volumes também."""
        for compose_name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
            cf = Path(temp_dir) / compose_name
            if cf.exists():
                subprocess.run(
                    ["docker", "compose", "-f", str(cf), "down", "-v", "--remove-orphans"],
                    capture_output=True, timeout=60,
                )
                log.info("[Teardown] docker compose down concluído.")
                return

    def _docker_rm(self, clone_id: str) -> None:
        """docker rm -f para containers individuais, e rmi para a imagem."""
        subprocess.run(["docker", "rm", "-f", clone_id], capture_output=True, timeout=30)
        log.info("[Teardown] docker rm -f %s concluído.", clone_id)

    def _remove_images(self, clone_id: str) -> None:
        """Remove imagens Docker geradas pelo clone (tag previswit/<clone_id>)."""
        image_tag = f"previswit/{clone_id}:ephemeral"
        subprocess.run(["docker", "rmi", "-f", image_tag], capture_output=True, timeout=30)
