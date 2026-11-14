"""Start hexward in the background when the user signs in.

Windows: a value under HKCU\\...\\Run (per-user, no administrator rights).
Linux:   an XDG autostart .desktop file.
The started process runs `gui --background`: no window, live guard on, alerts
delivered as desktop notifications.
"""

from __future__ import annotations

import sys
from pathlib import Path

from . import APP_NAME
from .core import IS_WINDOWS

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def command() -> str:
    """The exact command line registered for autostart."""
    if getattr(sys, "frozen", False):  # packaged .exe
        return f'"{sys.executable}" --background'
    exe = Path(sys.executable)
    windowless = exe.with_name("pythonw.exe")
    return f'"{windowless if windowless.is_file() else exe}" -m {APP_NAME} gui --background'


def _desktop_file() -> Path:
    return Path.home() / ".config" / "autostart" / f"{APP_NAME}.desktop"


def is_enabled(name: str = APP_NAME) -> bool:
    if IS_WINDOWS:
        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
                return bool(winreg.QueryValueEx(key, name)[0])
        except OSError:
            return False
    return _desktop_file().is_file()


def set_enabled(on: bool, name: str = APP_NAME) -> None:
    """Raises OSError when the platform or the registry refuses."""
    if IS_WINDOWS:
        import winreg

        if on:
            # A fresh Windows profile has no Run key yet, so create it when missing.
            with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, command())
        else:
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.DeleteValue(key, name)
            except FileNotFoundError:
                pass  # no key or no value: already off
        return
    if sys.platform == "darwin":
        raise OSError("autostart is not supported on macOS yet")
    path = _desktop_file()
    if on:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"[Desktop Entry]\nType=Application\nName={APP_NAME}\n"
                        f"Exec={command()}\nTerminal=false\nX-GNOME-Autostart-enabled=true\n", encoding="utf-8")
    else:
        path.unlink(missing_ok=True)
