"""
Provider registry — built-in defaults + user TOML overrides.
Handles provider detection by URL path and env var mapping.
"""

import tomllib
from pathlib import Path

CONFIG_PATH = Path.home() / ".re" / "providers.toml"

DEFAULT_PROVIDERS: dict[str, dict] = {
    "anthropic": {
        "upstream": "https://api.anthropic.com",
        "path_match": "exact",
        "path_patterns": ["messages", "messages/batches"],
        "env_var": "ANTHROPIC_BASE_URL",
        "env_value": "http://127.0.0.1:{port}",
    },
    "openai": {
        "upstream": "https://api.openai.com",
        "path_match": "suffix",
        "path_patterns": [
            "chat/completions",
            "responses",
            "completions",
            "embeddings",
            "images/generations",
            "images/edits",
            "audio/transcriptions",
            "audio/translations",
            "audio/speech",
            "moderations",
            "assistants",
            "fine_tuning/jobs",
            "batches",
            "files",
        ],
        "env_var": "OPENAI_BASE_URL",
        "env_value": "http://127.0.0.1:{port}/v1",
    },
}

RESERVED_PREFIXES = frozenset({"v1", "proxy", "ui"})


def load_providers(port: int = 8990) -> dict[str, dict]:
    providers = {}
    for name, cfg in DEFAULT_PROVIDERS.items():
        providers[name] = dict(cfg)

    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "rb") as f:
            user_config = tomllib.load(f)
        for name, cfg in user_config.get("providers", {}).items():
            if name in providers:
                providers[name].update(cfg)
            else:
                cfg.setdefault("path_match", "suffix")
                cfg.setdefault("path_patterns", ["chat/completions"])
                providers[name] = cfg

    for cfg in providers.values():
        if "env_value" in cfg:
            cfg["env_value"] = cfg["env_value"].replace("{port}", str(port))

    return providers


def detect_provider(
    path_after_prefix: str,
    headers: dict,
    providers: dict,
) -> tuple[str, str]:
    """Given the path after /v1/ (e.g. 'chat/completions'), return (provider_name, upstream_url).

    Checks providers in definition order. Anthropic uses exact match,
    OpenAI-compatible uses suffix match.
    """
    clean = path_after_prefix.split("?")[0].strip("/")

    for name, cfg in providers.items():
        match_mode = cfg.get("path_match", "suffix")
        for pattern in cfg.get("path_patterns", []):
            if match_mode == "exact":
                if clean == pattern or clean.startswith(pattern + "/"):
                    return name, cfg["upstream"]
            else:
                if clean == pattern or clean.endswith("/" + pattern):
                    return name, cfg["upstream"]

    if "x-api-key" in headers and "anthropic-version" in headers:
        return "anthropic", providers["anthropic"]["upstream"]

    return "openai", providers.get("openai", {}).get("upstream", "https://api.openai.com")


def resolve_named_provider(
    provider_name: str,
    providers: dict,
) -> str | None:
    """Return upstream URL for a named provider, or None if unknown."""
    cfg = providers.get(provider_name)
    if cfg:
        return cfg["upstream"]
    return None


def get_env_vars(providers: dict) -> dict[str, str]:
    """Return all env vars to inject for re run / re env."""
    env = {}
    for cfg in providers.values():
        if "env_var" in cfg and "env_value" in cfg:
            env[cfg["env_var"]] = cfg["env_value"]
    return env
