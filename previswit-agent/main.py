"""
main.py
Entry point for the local ASPM agent.
Initializes logging and starts the AgentWebSocket event loop.
"""

import asyncio
import logging
import sys

from core.ws_client import AgentWebSocket


def _configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
    )


async def _main() -> None:
    agent = AgentWebSocket()
    await agent.connect()


if __name__ == "__main__":
    _configure_logging()
    logging.getLogger(__name__).info("ASPM Agent starting …")
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        logging.getLogger(__name__).info("Agent stopped by user.")
