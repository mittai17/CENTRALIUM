"""Windows Service wrapper (pywin32 optional, import-guarded). Not exercised on Linux.

Install/run (manually, as Administrator, on the target host; nothing here installs anything):
    python -m centralium.agent.self_protection.windows_service install
    python -m centralium.agent.self_protection.windows_service start
    python -m centralium.agent.self_protection.windows_service stop|remove
The service runs the agent entry point given by ``agent_main`` in a worker thread; stopping the service sets a
stop event the agent loop must honour. Recovery actions (restart on failure) should be configured with
``sc.exe failure CentraliumAgent reset= 86400 actions= restart/5000/restart/5000/restart/30000``.
Windows ACL hardening of the install/data dirs is documented but NOT implemented here.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable

log = logging.getLogger("centralium.winservice")

try:  # pragma: no cover - Windows only
    import servicemanager  # type: ignore[import-untyped,unused-ignore]
    import win32event  # type: ignore[import-untyped,unused-ignore]
    import win32service  # type: ignore[import-untyped,unused-ignore]
    import win32serviceutil  # type: ignore[import-untyped,unused-ignore]

    HAVE_PYWIN32 = True
except ImportError:
    HAVE_PYWIN32 = False

SERVICE_NAME = "CentraliumAgent"
SERVICE_DISPLAY = "Centralium EDR Agent"
SERVICE_DESCRIPTION = "Centralium endpoint detection agent (transparent, auditable)."


def default_agent_main(stop: threading.Event) -> None:
    """Placeholder run loop: replace via ``set_agent_main``. Blocks until stop is set."""
    stop.wait()


_agent_main: Callable[[threading.Event], None] = default_agent_main


def set_agent_main(fn: Callable[[threading.Event], None]) -> None:
    global _agent_main
    _agent_main = fn


if HAVE_PYWIN32:  # pragma: no cover - Windows only

    class CentraliumService(win32serviceutil.ServiceFramework):  # type: ignore[misc]
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY
        _svc_description_ = SERVICE_DESCRIPTION

        def __init__(self, args: list[str]) -> None:
            super().__init__(args)
            self._stop_evt = threading.Event()
            self._hwnd = win32event.CreateEvent(None, 0, 0, None)

        def SvcStop(self) -> None:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self._stop_evt.set()
            win32event.SetEvent(self._hwnd)

        def SvcDoRun(self) -> None:
            servicemanager.LogInfoMsg(f"{SERVICE_NAME} starting")
            t = threading.Thread(target=_agent_main, args=(self._stop_evt,), name="agent-main")
            t.start()
            win32event.WaitForSingleObject(self._hwnd, win32event.INFINITE)
            t.join(30)
            servicemanager.LogInfoMsg(f"{SERVICE_NAME} stopped")


def main(argv: list[str] | None = None) -> int:
    if not HAVE_PYWIN32:
        log.error("pywin32 is not installed; the Windows service wrapper is unavailable")
        return 2
    win32serviceutil.HandleCommandLine(CentraliumService)  # pragma: no cover
    return 0  # pragma: no cover


if __name__ == "__main__":
    raise SystemExit(main())
