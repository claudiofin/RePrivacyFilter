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

## Limitations

- PII detection is strongest for English text. Italian and other languages have noticeably lower recall.
- CoreML acceleration is not available when the model uses external data files. Re falls back to CPU inference automatically (~200-400ms per request).
- The model is 5.5 GB in FP32. INT8 quantization is on the roadmap.
- Streaming responses are buffered per-chunk; very long streams may add minor latency.

## Disclaimer

Re does not guarantee complete PII removal. It is a defense-in-depth layer, not a compliance solution. Do not rely on it as the sole measure for GDPR, HIPAA, or any other regulatory framework. Always review your data handling practices independently.

## License

Apache 2.0. See [LICENSE](LICENSE) for the full text.
