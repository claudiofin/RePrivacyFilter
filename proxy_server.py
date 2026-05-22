"""
Privacy proxy server. Intercepts calls to OpenAI/Anthropic APIs,
scrubs PII via the ONNX privacy filter, forwards sanitized requests,
then de-anonymizes responses before returning them to the client.
"""

import asyncio
import copy
import json
import os
import secrets
import sqlite3
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Request, Response, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

from privacy_engine import PrivacyEngine

DB_PATH = Path(__file__).parent / "proxy_log.db"
STATIC_DIR = Path(__file__).parent / "static"

UPSTREAM_HOSTS = {
    "openai": "https://api.openai.com",
    "anthropic": "https://api.anthropic.com",
}

SESSION_TOKEN = os.environ.get("LEI_TOKEN", secrets.token_hex(16))

engine: PrivacyEngine | None = None
proxy_enabled: bool = True
http_client: httpx.AsyncClient | None = None
_db_lock: asyncio.Lock | None = None


def init_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS requests (
            id TEXT PRIMARY KEY,
            timestamp REAL,
            provider TEXT,
            endpoint TEXT,
            redacted_body TEXT,
            reverse_map TEXT,
            filter_ms REAL,
            upstream_ms REAL,
            pii_count INTEGER
        )
    """)
    conn.commit()
    conn.close()


async def log_request_async(
    req_id: str,
    provider: str,
    endpoint: str,
    redacted: str,
    reverse_map: dict,
    filter_ms: float,
    upstream_ms: float,
    pii_count: int,
):
    async with _db_lock:
        await asyncio.to_thread(
            _log_request_sync,
            req_id, provider, endpoint, redacted,
            reverse_map, filter_ms, upstream_ms, pii_count,
        )


def _log_request_sync(
    req_id, provider, endpoint, redacted,
    reverse_map, filter_ms, upstream_ms, pii_count,
):
    conn = sqlite3.connect(str(DB_PATH))
    try:
        conn.execute(
            "INSERT OR IGNORE INTO requests VALUES (?,?,?,?,?,?,?,?,?)",
            (
                req_id, time.time(), provider, endpoint,
                redacted,
                json.dumps(reverse_map, ensure_ascii=False),
                filter_ms, upstream_ms, pii_count,
            ),
        )
        conn.commit()
    finally:
        conn.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    global engine, http_client, _db_lock
    _db_lock = asyncio.Lock()
    model_path = os.environ.get("LEI_MODEL_PATH")
    if model_path:
        engine = PrivacyEngine(model_path=model_path, use_coreml=True)
    else:
        engine = PrivacyEngine(use_coreml=True)
    http_client = httpx.AsyncClient(timeout=httpx.Timeout(300.0, connect=30.0))
    init_db()
    yield
    if http_client:
        await http_client.aclose()


app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8990", "http://localhost:8990"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _check_dashboard_auth(request: Request):
    token = request.query_params.get("token") or request.headers.get("x-lei-token")
    if token != SESSION_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid token")


def _extract_text_fields(body: dict) -> list[tuple[list, int | str, str]]:
    fields = []

    if "prompt" in body and isinstance(body["prompt"], str):
        fields.append(([], "prompt", body["prompt"]))

    messages = body.get("messages", [])
    for i, msg in enumerate(messages):
        content = msg.get("content")
        if isinstance(content, str):
            fields.append((["messages", i], "content", content))
        elif isinstance(content, list):
            for j, block in enumerate(content):
                if isinstance(block, dict) and block.get("type") == "text":
                    fields.append(
                        (["messages", i, "content", j], "text", block["text"])
                    )

    if "input" in body and isinstance(body["input"], str):
        fields.append(([], "input", body["input"]))

    return fields


def _set_nested(obj, path: list, key, value):
    cur = obj
    for p in path:
        cur = cur[p]
    cur[key] = value


def _redact_body_sync(body: dict) -> tuple[dict, dict[str, str], int, float]:
    redacted = copy.deepcopy(body)
    combined_map: dict[str, str] = {}
    total_pii = 0
    t0 = time.time()

    for path, key, text in _extract_text_fields(body):
        sanitized, spans, rmap = engine.redact(text)
        _set_nested(redacted, path, key, sanitized)
        combined_map.update(rmap)
        total_pii += len(spans)

    ms = (time.time() - t0) * 1000
    return redacted, combined_map, total_pii, ms


async def _redact_body(body: dict) -> tuple[dict, dict[str, str], int, float]:
    return await asyncio.to_thread(_redact_body_sync, body)


def _deanon_response_text(text: str, reverse_map: dict[str, str]) -> str:
    return engine.deanonymize(text, reverse_map)


def _deanon_response_body(body: dict, reverse_map: dict[str, str]) -> dict:
    restored = copy.deepcopy(body)
    choices = restored.get("choices", [])
    for choice in choices:
        msg = choice.get("message", {})
        if isinstance(msg.get("content"), str):
            msg["content"] = _deanon_response_text(msg["content"], reverse_map)
        delta = choice.get("delta", {})
        if isinstance(delta.get("content"), str):
            delta["content"] = _deanon_response_text(delta["content"], reverse_map)

    content = restored.get("content", [])
    if isinstance(content, list):
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                block["text"] = _deanon_response_text(block["text"], reverse_map)

    return restored


def _detect_provider(path: str, headers: dict) -> tuple[str, str]:
    if path.endswith("/messages") or "/messages?" in path:
        return "anthropic", UPSTREAM_HOSTS["anthropic"]
    if path.endswith("/chat/completions") or "/chat/completions?" in path:
        return "openai", UPSTREAM_HOSTS["openai"]
    if path.endswith("/completions") or path.endswith("/embeddings"):
        return "openai", UPSTREAM_HOSTS["openai"]
    if "x-api-key" in headers and "anthropic-version" in headers:
        return "anthropic", UPSTREAM_HOSTS["anthropic"]
    return "openai", UPSTREAM_HOSTS["openai"]


# --- Dashboard API (auth required) ---

@app.get("/proxy/status")
async def get_status():
    return {
        "enabled": proxy_enabled,
        "providers": engine.active_providers if engine else [],
        "model_loaded": engine is not None,
    }


@app.post("/proxy/toggle")
async def toggle_proxy(request: Request):
    _check_dashboard_auth(request)
    global proxy_enabled
    proxy_enabled = not proxy_enabled
    return {"enabled": proxy_enabled}


@app.get("/proxy/stats")
async def get_stats(request: Request):
    _check_dashboard_auth(request)

    def _query():
        conn = sqlite3.connect(str(DB_PATH))
        row = conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(pii_count),0), "
            "COALESCE(AVG(filter_ms),0), COALESCE(AVG(upstream_ms),0) "
            "FROM requests"
        ).fetchone()
        conn.close()
        return row

    row = await asyncio.to_thread(_query)
    return {
        "total": row[0],
        "pii": int(row[1]),
        "avg_filter": row[2],
        "avg_upstream": row[3],
    }


@app.get("/proxy/logs")
async def get_logs(request: Request, limit: int = 50, offset: int = 0):
    _check_dashboard_auth(request)

    def _query():
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM requests ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    return await asyncio.to_thread(_query)


@app.get("/ui", response_class=HTMLResponse)
async def ui(request: Request):
    _check_dashboard_auth(request)
    html_path = STATIC_DIR / "index.html"
    content = html_path.read_text().replace(
        "let TOKEN = '';",
        f"let TOKEN = '{SESSION_TOKEN}';",
    )
    return HTMLResponse(content=content)


# --- Proxy handler (no auth — clients send their own API keys) ---

@app.api_route(
    "/v1/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"]
)
async def proxy_handler(request: Request, path: str):
    headers_dict = dict(request.headers)
    provider, upstream_base = _detect_provider(
        request.url.path, headers_dict
    )

    raw_body = await request.body()
    upstream_url = f"{upstream_base}/v1/{path}"

    forward_headers = {
        k: v
        for k, v in headers_dict.items()
        if k.lower() not in ("host", "content-length", "transfer-encoding")
    }

    if not proxy_enabled or not raw_body or request.method != "POST":
        resp = await http_client.request(
            method=request.method,
            url=upstream_url,
            headers=forward_headers,
            content=raw_body,
        )
        return Response(
            content=resp.content,
            status_code=resp.status_code,
            headers=dict(resp.headers),
        )

    try:
        body = json.loads(raw_body)
    except json.JSONDecodeError:
        resp = await http_client.request(
            method=request.method,
            url=upstream_url,
            headers=forward_headers,
            content=raw_body,
        )
        return Response(
            content=resp.content,
            status_code=resp.status_code,
            headers=dict(resp.headers),
        )

    is_streaming = body.get("stream", False)

    redacted_body, reverse_map, pii_count, filter_ms = await _redact_body(body)

    redacted_json = json.dumps(redacted_body, ensure_ascii=False)

    t_up = time.time()

    if is_streaming:
        req = http_client.build_request(
            method="POST",
            url=upstream_url,
            headers=forward_headers,
            content=redacted_json.encode(),
        )
        upstream_resp = await http_client.send(req, stream=True)

        resp_headers = {
            k: v for k, v in upstream_resp.headers.items()
            if k.lower() not in ("content-length", "transfer-encoding", "content-encoding")
        }

        collected_chunks: list[str] = []
        max_tag_len = max((len(t) for t in reverse_map), default=0) if reverse_map else 0

        async def stream_with_deanon():
            buffer = ""
            try:
                async for raw_bytes in upstream_resp.aiter_bytes():
                    text = raw_bytes.decode("utf-8", errors="replace")
                    collected_chunks.append(text)

                    if not reverse_map:
                        yield text
                        continue

                    buffer += text
                    safe_point = len(buffer) - max_tag_len - 1
                    if safe_point <= 0:
                        continue

                    to_send = buffer[:safe_point]
                    buffer = buffer[safe_point:]
                    for tag, original in reverse_map.items():
                        to_send = to_send.replace(tag, original)
                    yield to_send

                if buffer:
                    for tag, original in reverse_map.items():
                        buffer = buffer.replace(tag, original)
                    yield buffer

            finally:
                await upstream_resp.aclose()
                upstream_ms = (time.time() - t_up) * 1000
                req_id = uuid.uuid4().hex[:12]
                await log_request_async(
                    req_id, provider, f"/v1/{path}",
                    redacted_json[:2000], reverse_map,
                    filter_ms, upstream_ms, pii_count,
                )

        return StreamingResponse(
            stream_with_deanon(),
            status_code=upstream_resp.status_code,
            headers=resp_headers,
            media_type=upstream_resp.headers.get("content-type", "text/event-stream"),
        )
    else:
        resp = await http_client.request(
            method="POST",
            url=upstream_url,
            headers=forward_headers,
            content=redacted_json.encode(),
        )
        upstream_ms = (time.time() - t_up) * 1000

        try:
            resp_body = resp.json()
            if reverse_map:
                restored_body = _deanon_response_body(resp_body, reverse_map)
            else:
                restored_body = resp_body
        except Exception:
            restored_body = resp.text

        req_id = uuid.uuid4().hex[:12]
        await log_request_async(
            req_id, provider, f"/v1/{path}",
            redacted_json[:2000], reverse_map,
            filter_ms, upstream_ms, pii_count,
        )

        if isinstance(restored_body, dict):
            return JSONResponse(
                content=restored_body, status_code=resp.status_code
            )
        return Response(
            content=restored_body.encode() if isinstance(restored_body, str) else resp.content,
            status_code=resp.status_code,
            headers=dict(resp.headers),
        )
