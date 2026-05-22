"""
macOS menu bar app for the Privacy Filter proxy.
Uses rumps for the menu bar icon and manages the uvicorn server in a background thread.
"""

import subprocess
import sys
import threading
import webbrowser
from pathlib import Path

import rumps
import requests

PROXY_PORT = 8990
PROXY_URL = f"http://127.0.0.1:{PROXY_PORT}"
TOKEN_FILE = Path.home() / ".re" / ".session_token"


def _read_token() -> str:
    try:
        return TOKEN_FILE.read_text().strip()
    except FileNotFoundError:
        return ""


def _auth_headers() -> dict:
    token = _read_token()
    return {"X-Re-Token": token} if token else {}


class PrivacyFilterApp(rumps.App):
    def __init__(self):
        super().__init__(
            "RePrivacyFilter",
            icon=None,
            title="🛡️",
            quit_button=None,
        )
        self.server_thread = None
        self.server_process = None
        self._proxy_on = True

        self.menu = [
            rumps.MenuItem("Status: Loading...", callback=None),
            None,
            rumps.MenuItem("Toggle Filter", callback=self.toggle_filter),
            rumps.MenuItem("Open Dashboard", callback=self.open_dashboard),
            None,
            rumps.MenuItem(
                f"Proxy: 127.0.0.1:{PROXY_PORT}", callback=None
            ),
            None,
            rumps.MenuItem("Quit", callback=self.quit_app),
        ]

        self._start_server()

    def _start_server(self):
        def run():
            self.server_process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "uvicorn",
                    "proxy_server:app",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(PROXY_PORT),
                    "--log-level",
                    "warning",
                ],
                cwd=str(__import__("pathlib").Path(__file__).parent),
            )
            self.server_process.wait()

        self.server_thread = threading.Thread(target=run, daemon=True)
        self.server_thread.start()

        def check_ready():
            import time

            for _ in range(30):
                time.sleep(1)
                try:
                    r = requests.get(f"{PROXY_URL}/health", timeout=2)
                    if r.ok:
                        sr = requests.get(f"{PROXY_URL}/proxy/status", headers=_auth_headers(), timeout=2)
                        data = sr.json() if sr.ok else {}
                        prov = ", ".join(data.get("providers", []))
                        self.menu["Status: Loading..."].title = (
                            f"Filter ON — {prov}"
                        )
                        self.title = "🛡️"
                        return
                except Exception:
                    pass
            self.menu["Status: Loading..."].title = "Status: Failed to start"
            self.title = "⚠️"

        threading.Thread(target=check_ready, daemon=True).start()

    @rumps.clicked("Toggle Filter")
    def toggle_filter(self, sender):
        try:
            r = requests.post(f"{PROXY_URL}/proxy/toggle", headers=_auth_headers(), timeout=5)
            data = r.json()
            self._proxy_on = data["enabled"]
            status_item = list(self.menu.values())[0]
            if self._proxy_on:
                status_item.title = "Filter ON"
                self.title = "🛡️"
            else:
                status_item.title = "Filter OFF (passthrough)"
                self.title = "🔓"
        except Exception as e:
            rumps.alert("Error", str(e))

    @rumps.clicked("Open Dashboard")
    def open_dashboard(self, sender):
        token = _read_token()
        url = f"{PROXY_URL}/ui?token={token}" if token else f"{PROXY_URL}/ui"
        webbrowser.open(url)

    @rumps.clicked("Quit")
    def quit_app(self, sender):
        if self.server_process:
            self.server_process.terminate()
        rumps.quit_application()


if __name__ == "__main__":
    PrivacyFilterApp().run()
