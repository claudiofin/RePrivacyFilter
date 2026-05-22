"""
Privacy proxy server. Intercepts calls to OpenAI/Anthropic APIs,
scrubs PII via the ONNX privacy filter, forwards sanitized requests,
then de-anonymizes responses before returning them to the client.
"""

import asyncio
import copy
import json
import logging
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

from privacy_engine import PrivacyEngine, parse_categories
from providers import load_providers, detect_provider, resolve_named_provider, RESERVED_PREFIXES

DB_PATH = Path(__file__).parent / "proxy_log.db"
STATIC_DIR = Path(__file__).parent / "static"
PORT = int(os.environ.get("RE_PORT", 8990))

SESSION_TOKEN = os.environ.get("RE_TOKEN", secrets.token_hex(16))
TOKEN_FILE = Path.home() / ".re" / ".session_token"
LOG_PII = os.environ.get("RE_LOG_PII", "false").lower() in ("1", "true", "yes")

log = logging.getLogger("re")

engine: PrivacyEngine | None = None
proxy_enabled: bool = True
http_client: httpx.AsyncClient | None = None
_db_lock: asyncio.Lock | None = None
_providers: dict = {}


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
                json.dumps(reverse_map, ensure_ascii=False) if LOG_PII else "{}",
                filter_ms, upstream_ms, pii_count,
            ),
        )
        conn.commit()
    finally:
        conn.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    global engine, http_client, _db_lock, _providers
    _db_lock = asyncio.Lock()
    _providers = load_providers(PORT)
    TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    TOKEN_FILE.write_text(SESSION_TOKEN)
    model_path = os.environ.get("RE_MODEL_PATH")
    categories_raw = os.environ.get("RE_REDACT", "")
    confidence = float(os.environ.get("RE_CONFIDENCE", "0.0"))
    cache_size = int(os.environ.get("RE_CACHE_SIZE", "512"))
    categories = parse_categories(categories_raw) if categories_raw else None

    engine = PrivacyEngine(
        model_path=model_path if model_path else None,
        use_coreml=True,
        categories=categories,
        confidence_threshold=confidence,
        cache_size=cache_size,
    )
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
    token = request.query_params.get("token") or request.headers.get("x-re-token")
    if token != SESSION_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid token")


# --- Recursive text extraction / de-anonymization ---

_DROP_RESPONSE_HEADERS = frozenset({
    "set-cookie", "content-encoding", "transfer-encoding",
    "content-length", "content-security-policy",
})


def _filter_response_headers(headers) -> dict[str, str]:
    return {
        k: v for k, v in headers.items()
        if k.lower() not in _DROP_RESPONSE_HEADERS
    }


SKIP_KEYS = frozenset({
    "model", "role", "type", "object", "id", "created", "index",
    "system_fingerprint", "logprobs", "finish_reason", "stop_reason",
    "encoding_format", "tool_call_id", "citation", "response_format",
    "top_p", "temperature", "max_tokens", "max_completion_tokens",
    "stream", "stream_options", "n", "stop", "presence_penalty",
    "frequency_penalty", "seed", "service_tier", "top_k",
    "anthropic_version", "x-api-key",
    "url", "source", "media_type", "file_id",
    "training_file", "validation_file",
})

MIN_TEXT_LEN = 8


def _redact_tree(obj, parent=None, key=None, combined_map=None, stats=None):
    """Walk obj in-place, redact all string values that could contain PII."""
    if combined_map is None:
        combined_map = {}
    if stats is None:
        stats = [0]

    if isinstance(obj, dict):
        for k in list(obj.keys()):
            if k in SKIP_KEYS:
                continue
            _redact_tree(obj[k], obj, k, combined_map, stats)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _redact_tree(v, obj, i, combined_map, stats)
    elif isinstance(obj, str) and parent is not None and len(obj) >= MIN_TEXT_LEN:
        if obj.startswith("data:"):
            return
        if obj.startswith(("http://", "https://")) and "\n" not in obj and len(obj) < 2048:
            return
        sanitized, spans, rmap = engine.redact(obj)
        if spans:
            parent[key] = sanitized
            combined_map.update(rmap)
            stats[0] += len(spans)

    return combined_map, stats[0]


def _redact_body_sync(body: dict) -> tuple[dict, dict[str, str], int, float]:
    redacted = copy.deepcopy(body)
    t0 = time.time()
    combined_map, total_pii = _redact_tree(redacted)
    ms = (time.time() - t0) * 1000
    return redacted, combined_map, total_pii, ms


async def _redact_body(body: dict) -> tuple[dict, dict[str, str], int, float]:
    return await asyncio.to_thread(_redact_body_sync, body)


def _deanon_tree(obj, reverse_map: dict[str, str]):
    """Walk obj in-place, replace all placeholder tags with originals."""
    if isinstance(obj, dict):
        for k in obj:
            if isinstance(obj[k], str):
                for tag, original in reverse_map.items():
                    if tag in obj[k]:
                        obj[k] = obj[k].replace(tag, original)
            else:
                _deanon_tree(obj[k], reverse_map)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            if isinstance(v, str):
                for tag, original in reverse_map.items():
                    if tag in obj[i]:
                        obj[i] = obj[i].replace(tag, original)
            else:
                _deanon_tree(v, reverse_map)


def _deanon_response_body(body: dict, reverse_map: dict[str, str]) -> dict:
    restored = copy.deepcopy(body)
    _deanon_tree(restored, reverse_map)
    return restored


# --- Dashboard API (auth required) ---

@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/proxy/status")
async def get_status(request: Request):
    _check_dashboard_auth(request)
    return {
        "enabled": proxy_enabled,
        "providers": engine.active_providers if engine else [],
        "model_loaded": engine is not None,
        "configured_providers": list(_providers.keys()),
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


# --- Proxy handlers (no auth — clients send their own API keys) ---

async def _proxy_core(
    request: Request,
    provider: str,
    upstream_base: str,
    upstream_path: str,
):
    """Shared proxy logic for both auto-detect and named-provider routes."""
    headers_dict = dict(request.headers)
    raw_body = await request.body()
    upstream_url = f"{upstream_base}/{upstream_path}"

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
            headers=_filter_response_headers(resp.headers),
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
            headers=_filter_response_headers(resp.headers),
        )

    is_streaming = body.get("stream", False)
    log_endpoint = f"/{upstream_path}"

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

        max_tag_len = max((len(t) for t in reverse_map), default=0) if reverse_map else 0

        async def stream_with_deanon():
            buffer = ""
            try:
                async for raw_bytes in upstream_resp.aiter_bytes():
                    text = raw_bytes.decode("utf-8", errors="replace")

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
                    req_id, provider, log_endpoint,
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
            req_id, provider, log_endpoint,
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
            headers=_filter_response_headers(resp.headers),
        )


@app.api_route(
    "/v1/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"]
)
async def proxy_v1(request: Request, path: str):
    """Backward-compatible route: auto-detect provider from path/headers."""
    headers_dict = dict(request.headers)
    provider, upstream_base = detect_provider(path, headers_dict, _providers)
    return await _proxy_core(request, provider, upstream_base, f"v1/{path}")


@app.api_route(
    "/p/{provider_name}/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"]
)
async def proxy_named(request: Request, provider_name: str, path: str):
    """Explicit provider route: /p/groq/v1/chat/completions -> api.groq.com/openai/v1/chat/completions"""
    upstream_base = resolve_named_provider(provider_name, _providers)
    if not upstream_base:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown provider '{provider_name}'. Configured: {list(_providers.keys())}",
        )
    return await _proxy_core(request, provider_name, upstream_base, path)
