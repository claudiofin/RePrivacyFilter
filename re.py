#!/usr/bin/env python3
"""
re — Privacy filter proxy CLI.
Intercepts OpenAI/Anthropic API calls, scrubs PII locally via ONNX,
shows live logs in the terminal.
"""

import json
import os
import signal
import sqlite3
import sys
import threading
import time
from pathlib import Path

os.environ["ORT_LOG_LEVEL"] = "ERROR"
os.environ["PYTHONWARNINGS"] = "ignore"

import uvicorn
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

DB_PATH = Path(__file__).parent / "proxy_log.db"
PORT = 8990
console = Console()

BANNER = r"""
[bold blue]  ____       [/]
[bold blue] |  _ \ ___  [/]  [bold white]Privacy Filter Proxy[/]
[bold blue] | |_) / _ \ [/]  [dim]ONNX · local · real-time[/]
[bold blue] |  _ <  __/ [/]
[bold blue] |_| \_\___| [/]
"""


def get_stats() -> dict:
    try:
        conn = sqlite3.connect(str(DB_PATH))
        row = conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(pii_count),0), "
            "COALESCE(AVG(filter_ms),0), COALESCE(AVG(upstream_ms),0) "
            "FROM requests"
        ).fetchone()
        conn.close()
        return {
            "total": row[0],
            "pii": int(row[1]),
            "avg_filter": row[2],
            "avg_upstream": row[3],
        }
    except Exception:
        return {"total": 0, "pii": 0, "avg_filter": 0, "avg_upstream": 0}


def get_recent_logs(limit: int = 15) -> list[dict]:
    try:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM requests ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def format_body_preview(body_json: str, max_len: int = 80) -> str:
    try:
        body = json.loads(body_json)
        msgs = body.get("messages", [])
        for msg in reversed(msgs):
            content = msg.get("content", "")
            if isinstance(content, str) and content.strip():
                return content[:max_len] + ("..." if len(content) > max_len else "")
        if "prompt" in body:
            p = body["prompt"]
            return p[:max_len] + ("..." if len(p) > max_len else "")
    except Exception:
        pass
    return body_json[:max_len]


def time_ago(ts: float) -> str:
    delta = time.time() - ts
    if delta < 60:
        return f"{int(delta)}s ago"
    if delta < 3600:
        return f"{int(delta/60)}m ago"
    return f"{int(delta/3600)}h ago"


def build_dashboard(show_detail: int | None = None) -> Table:
    stats = get_stats()
    logs = get_recent_logs()

    grid = Table.grid(padding=(0, 1))
    grid.add_column()

    header = Table(box=None, show_header=False, padding=(0, 3))
    header.add_column(style="bold cyan", width=20)
    header.add_column(style="bold yellow", width=20)
    header.add_column(style="bold green", width=20)
    header.add_column(style="dim", width=20)
    header.add_row(
        f"Requests: {stats['total']}",
        f"PII found: {stats['pii']}",
        f"Filter: {stats['avg_filter']:.0f}ms",
        f"Upstream: {stats['avg_upstream']:.0f}ms",
    )
    grid.add_row(header)
    grid.add_row(Text(""))

    if not logs:
        grid.add_row(Text("  Waiting for requests...", style="dim italic"))
        return grid

    log_table = Table(
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold",
        padding=(0, 1),
        expand=True,
    )
    log_table.add_column("", width=3)
    log_table.add_column("Provider", width=10)
    log_table.add_column("Endpoint", width=24)
    log_table.add_column("PII", width=5, justify="right")
    log_table.add_column("Filter", width=8, justify="right")
    log_table.add_column("When", width=8)
    log_table.add_column("Preview", ratio=1)

    for i, log in enumerate(logs):
        prov = (log.get("provider") or "openai").upper()
        prov_style = "green" if prov == "OPENAI" else "magenta"
        pii_count = log.get("pii_count", 0)
        pii_style = "yellow bold" if pii_count > 0 else "dim"
        marker = ">" if i == show_detail else " "

        preview = format_body_preview(log.get("redacted_body", ""), 50)

        log_table.add_row(
            Text(marker, style="bold cyan"),
            Text(prov, style=prov_style),
            Text(log.get("endpoint", ""), style="dim"),
            Text(str(pii_count), style=pii_style),
            Text(f"{log.get('filter_ms', 0):.0f}ms", style="green"),
            Text(time_ago(log.get("timestamp", 0)), style="dim"),
            Text(preview, style="white", overflow="ellipsis"),
        )

    grid.add_row(log_table)

    if show_detail is not None and 0 <= show_detail < len(logs):
        log = logs[show_detail]
        detail = Table.grid(padding=(0, 1))
        detail.add_column(ratio=1)
        detail.add_column(ratio=1)

        orig = format_body_preview(log.get("original_body", ""), 300)
        redc = format_body_preview(log.get("redacted_body", ""), 300)

        detail.add_row(
            Panel(orig, title="[bold]Original", border_style="yellow", width=55),
            Panel(redc, title="[bold]Sanitized", border_style="cyan", width=55),
        )

        rmap = {}
        try:
            rmap = json.loads(log.get("reverse_map", "{}"))
        except Exception:
            pass

        if rmap:
            map_lines = []
            for tag, val in rmap.items():
                map_lines.append(f"  [cyan]{tag}[/] → [yellow]{val}[/]")
            detail.add_row(
                Panel(
                    "\n".join(map_lines),
                    title="[bold]PII Mapping (local only)",
                    border_style="dim",
                ),
                Text(""),
            )

        grid.add_row(Text(""))
        grid.add_row(detail)

    return grid


def run_server():
    config = uvicorn.Config(
        "proxy_server:app",
        host="127.0.0.1",
        port=PORT,
        log_level="error",
    )
    server = uvicorn.Server(config)
    server.run()


def _start_proxy_background():
    """Start the proxy server in a background thread, suppress ONNX init noise."""
    devnull = open(os.devnull, "w")

    def _run_quiet():
        old_stderr = os.dup(2)
        os.dup2(devnull.fileno(), 2)
        try:
            run_server()
        finally:
            os.dup2(old_stderr, 2)
            os.close(old_stderr)
            devnull.close()

    server_thread = threading.Thread(target=_run_quiet, daemon=True)
    server_thread.start()
    return server_thread


def _wait_for_proxy(timeout: int = 20) -> bool:
    import urllib.request
    for _ in range(timeout * 2):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{PORT}/proxy/status", timeout=1)
            return True
        except Exception:
            time.sleep(0.5)
    return False


def _get_session_token() -> str:
    from proxy_server import SESSION_TOKEN
    return SESSION_TOKEN


def _dashboard_url() -> str:
    return f"http://127.0.0.1:{PORT}/ui?token={_get_session_token()}"


def cmd_run(args: list[str]):
    """re run <command> — start proxy, run command with env vars set, show logs."""
    if not args:
        console.print("[red]Usage: re run <command>[/]")
        console.print("[dim]  Example: re run python my_script.py[/]")
        sys.exit(1)

    console.print(BANNER)
    console.print(f"  [bold green]Starting proxy...[/]")

    _start_proxy_background()

    if not _wait_for_proxy():
        console.print("[red]  Failed to start proxy[/]")
        sys.exit(1)

    console.print(f"  [bold green]Proxy ready on[/] [bold white underline]http://127.0.0.1:{PORT}/v1/[/]")
    console.print(f"  [dim]Running:[/] [bold]{' '.join(args)}[/]")
    console.print(f"  [dim]Dashboard:[/] [bold white underline]{_dashboard_url()}[/]")
    console.print()

    from providers import load_providers, get_env_vars

    import subprocess
    env = os.environ.copy()
    providers = load_providers(PORT)
    env.update(get_env_vars(providers))

    try:
        result = subprocess.run(args, env=env)
        sys.exit(result.returncode)
    except KeyboardInterrupt:
        pass
    except FileNotFoundError:
        console.print(f"[red]  Command not found: {args[0]}[/]")
        sys.exit(127)
    finally:
        stats = get_stats()
        if stats["total"] > 0:
            console.print()
            console.print(f"  [bold]Session summary:[/] {stats['total']} requests, {stats['pii']} PII items filtered")


def cmd_env():
    """re env — print env vars to eval in your shell."""
    from providers import load_providers, get_env_vars
    providers = load_providers(PORT)
    for var, val in get_env_vars(providers).items():
        print(f"export {var}={val}")


def cmd_start():
    """re (no args) or re start — interactive mode with live dashboard."""
    console.print(BANNER)
    _start_proxy_background()

    if not _wait_for_proxy():
        console.print("[red]  Failed to start proxy[/]")
        sys.exit(1)

    console.print(
        f"  [bold green]Proxy listening on[/] [bold white underline]http://127.0.0.1:{PORT}/v1/[/]"
    )
    console.print()
    console.print("  [bold]To route traffic through Re, use one of:[/]")
    console.print(f"    [cyan]./re run <command>[/]        [dim]# auto-sets env vars for that command[/]")
    console.print(f"    [cyan]eval \"$(./re env)\"[/]        [dim]# sets env vars in current shell[/]")
    console.print()
    console.print(
        f"  [dim]Dashboard:[/] [bold white underline]{_dashboard_url()}[/]"
    )
    console.print(
        "  [dim]Press[/] [bold]Ctrl+C[/] [dim]to stop[/]"
    )
    console.print()

    selected = None
    detail_open = False
    last_count = 0

    try:
        with Live(
            build_dashboard(),
            console=console,
            refresh_per_second=1,
            transient=False,
        ) as live:
            while True:
                stats = get_stats()
                if stats["total"] > last_count:
                    last_count = stats["total"]
                    if not detail_open:
                        selected = 0

                detail_idx = selected if detail_open else None
                live.update(build_dashboard(show_detail=detail_idx))
                time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n  [bold red]Stopped.[/]")
        sys.exit(0)


def main():
    args = sys.argv[1:]

    if not args or args[0] == "start":
        cmd_start()
    elif args[0] == "run":
        cmd_run(args[1:])
    elif args[0] == "env":
        cmd_env()
    else:
        console.print(f"[bold]re[/] — Privacy Filter Proxy\n")
        console.print("  [cyan]re[/]              Start proxy with live dashboard")
        console.print("  [cyan]re run <cmd>[/]    Run a command through the proxy")
        console.print("  [cyan]re env[/]          Print env vars (use with eval)")
        sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
    main()
