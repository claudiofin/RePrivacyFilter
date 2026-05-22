# Re -- Local Privacy Proxy for LLM APIs

Re intercepts OpenAI and Anthropic API calls, scrubs PII locally using an ONNX model, forwards sanitized requests to the cloud, and de-anonymizes responses before returning them to your application.

## How it works

```
                   +---------------------------+
  Client App ----->| Re Proxy                  |-----> Cloud API
                   |  1. Detect & mask PII     |      (any provider)
                   |  2. Forward clean request  |
                   |                           |
  Client App <-----| Re Proxy                  |<----- Cloud API
                   |  3. De-anonymize response  |
                   +---------------------------+
```

All PII detection and replacement runs on your machine. No personal data leaves localhost.

## Quickstart

```bash
git clone https://github.com/claudiofin/RePrivacyFilter.git
cd RePrivacyFilter
./setup.sh          # creates venv, installs deps, downloads model
./re run python my_script.py
```

`./re run` sets the proxy env vars, launches the local proxy, runs your command, and tears everything down on exit.

## Usage

| Command                  | Description                                  |
|--------------------------|----------------------------------------------|
| `./re run <cmd>`         | Wrap any command through the privacy proxy    |
| `./re`                   | Open the interactive dashboard                |
| `./re env`               | Print env vars for manual shell eval          |

The dashboard is available at `http://127.0.0.1:8990/ui` while the proxy is running. It shows intercepted requests, detected entities, and filtering statistics.

## Model

Re uses [OpenAI's Privacy Filter](https://huggingface.co/openai/privacy-filter), a 1.5B-parameter MoE model (Apache 2.0). The ONNX model is downloaded automatically on first run (~772 MB, q4f16 quantized).

To use a different variant or a custom model path:

```bash
export RE_MODEL_PATH=/path/to/model.onnx
```

Available ONNX variants on HuggingFace (in `onnx/` directory):

| Variant | Size | Notes |
|---------|------|-------|
| `model_q4f16` | 772 MB | Default. Best speed/size tradeoff |
| `model_q4` | 875 MB | INT4 quantized |
| `model_quantized` | 1.5 GB | INT8 quantized |
| `model_fp16` | 2.6 GB | Half precision |
| `model` | 5.3 GB | Full FP32 |

## Supported Providers

OpenAI and Anthropic work out of the box. Any OpenAI-compatible provider (Groq, Together, Ollama, Mistral, DeepSeek, xAI, LM Studio, Fireworks, Perplexity) can be added via config.

**Built-in (zero config):**

- `OPENAI_BASE_URL=http://127.0.0.1:8990/v1`
- `ANTHROPIC_BASE_URL=http://127.0.0.1:8990`

**Custom providers** -- create `~/.re/providers.toml`:

```toml
[providers.groq]
upstream = "https://api.groq.com/openai"
env_var = "GROQ_BASE_URL"
env_value = "http://127.0.0.1:{port}/p/groq"

[providers.ollama]
upstream = "http://localhost:11434"
env_var = "OLLAMA_HOST"
env_value = "http://127.0.0.1:{port}/p/ollama"
```

`./re run` and `./re env` automatically set env vars for all configured providers. See `providers.example.toml` for more examples.

## Configuration

All configuration is via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `RE_PORT` | `8990` | Proxy listen port |
| `RE_MODEL_PATH` | auto-detect | Path to custom ONNX model |
| `RE_TOKEN` | random per session | Dashboard auth token (auto-generated) |
| `RE_LOG_PII` | `false` | Store PII mapping in local DB for dashboard display. When `false` (default), the reverse map is kept in memory only for the duration of each request and is **not** written to disk. Set to `true` to enable the full original-vs-sanitized diff view in the dashboard. |

## Security

Re is designed for local, single-user use. The proxy binds to `127.0.0.1` only and is not meant to be exposed to the network.

**Authentication:** All dashboard and management endpoints require a session token (auto-generated or set via `RE_TOKEN`). API proxy endpoints (`/v1/...`, `/p/...`) do not require a Re token -- clients authenticate directly with their upstream API keys, which are forwarded as-is.

**PII storage:** By default, PII mappings are **not** persisted to disk. The local SQLite database (`proxy_log.db`) stores only redacted request bodies and aggregate stats. Set `RE_LOG_PII=true` if you want the dashboard to show the full original-vs-sanitized diff (the mapping is then stored locally in plain text).

**API keys:** Re forwards your API keys to the upstream provider but never logs, stores, or inspects them.

**Provider validation:** Custom provider names in `providers.toml` are validated against reserved route names (`v1`, `ui`, `proxy`) and upstream URLs must use `http://` or `https://`.

## Limitations

- PII detection is strongest for English text. Italian and other languages have noticeably lower recall.
- CoreML acceleration is not available when the model uses external data files. Re falls back to CPU inference automatically (~200-400ms per request).
- Streaming responses are buffered per-chunk; very long streams may add minor latency.
- The model may produce false positives on common English names used as words (e.g. "Will", "May") and false negatives on non-standard PII formats (e.g. Italian codice fiscale). Custom regex rules via `providers.toml` are planned.
- De-anonymization relies on exact placeholder matching. If the LLM rephrases a placeholder (e.g. turns `<PRIVATE_PERSON_1>` into "the person mentioned"), the original value cannot be restored.
- No rate limiting. A runaway client loop can saturate CPU with ONNX inference.
- No HTTPS. Acceptable on localhost; do not bind to `0.0.0.0` without a TLS terminator.

## Disclaimer

Re does not guarantee complete PII removal. It is a defense-in-depth layer, not a compliance solution. Do not rely on it as the sole measure for GDPR, HIPAA, or any other regulatory framework. Always review your data handling practices independently.

## License

Apache 2.0. See [LICENSE](LICENSE) for the full text.
