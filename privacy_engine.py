"""
ONNX-based privacy filter engine using OpenAI's Privacy Filter model.
Tokenizes with o200k_base, runs inference via ONNX Runtime (CoreML/CPU),
decodes BIOES labels, and replaces PII spans with placeholders.
"""

import bisect
import hashlib
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import numpy as np
import onnxruntime as ort
import tiktoken

HF_REPO = "openai/privacy-filter"
HF_VARIANT = "model_q4f16"
ONNX_MODEL_PATH = Path.home() / "privacy-filter" / "PrivacyFilter.onnx"


def download_model(variant: str = HF_VARIANT) -> Path:
    """Download ONNX model from HuggingFace if not cached. Returns path to .onnx file."""
    from huggingface_hub import hf_hub_download
    onnx_file = f"onnx/{variant}.onnx"
    data_file = f"onnx/{variant}.onnx_data"
    hf_hub_download(HF_REPO, data_file)
    return Path(hf_hub_download(HF_REPO, onnx_file))

SPAN_CLASSES = [
    "O",
    "account_number",
    "private_address",
    "private_date",
    "private_email",
    "private_person",
    "private_phone",
    "private_url",
    "secret",
]

TOKEN_LABELS: list[str] = ["O"]
for cls in SPAN_CLASSES[1:]:
    TOKEN_LABELS.extend([f"B-{cls}", f"I-{cls}", f"E-{cls}", f"S-{cls}"])

PLACEHOLDER_MAP = {
    "account_number": "<ACCOUNT_NUMBER>",
    "private_address": "<PRIVATE_ADDRESS>",
    "private_date": "<PRIVATE_DATE>",
    "private_email": "<PRIVATE_EMAIL>",
    "private_person": "<PRIVATE_PERSON>",
    "private_phone": "<PRIVATE_PHONE>",
    "private_url": "<PRIVATE_URL>",
    "secret": "<SECRET>",
}

TOKEN_TO_SPAN = {}
TOKEN_BOUNDARY = {}
for i, label in enumerate(TOKEN_LABELS):
    if label == "O":
        TOKEN_TO_SPAN[i] = 0
        TOKEN_BOUNDARY[i] = None
    else:
        boundary, cls_name = label.split("-", 1)
        TOKEN_TO_SPAN[i] = SPAN_CLASSES.index(cls_name)
        TOKEN_BOUNDARY[i] = boundary

# --- Category whitelist helpers ---

CATEGORY_ALIASES: dict[str, str] = {}
for _cat in SPAN_CLASSES[1:]:
    CATEGORY_ALIASES[_cat] = _cat
    _short = _cat.removeprefix("private_")
    if _short != _cat:
        CATEGORY_ALIASES[_short] = _cat
CATEGORY_ALIASES["name"] = "private_person"
CATEGORY_ALIASES["account"] = "account_number"

ALL_CATEGORIES = frozenset(SPAN_CLASSES[1:])


def parse_categories(raw: str) -> frozenset[str]:
    """Parse RE_REDACT value (comma-separated) into canonical category names.

    Accepts both full names (``private_email``) and short aliases (``email``).
    ``*`` or empty string means all categories.
    """
    if not raw or raw.strip() == "*":
        return ALL_CATEGORIES
    cats: set[str] = set()
    for tok in raw.split(","):
        tok = tok.strip().lower()
        if not tok:
            continue
        if tok not in CATEGORY_ALIASES:
            raise ValueError(
                f"Unknown PII category '{tok}'. "
                f"Valid: {sorted(CATEGORY_ALIASES)}"
            )
        cats.add(CATEGORY_ALIASES[tok])
    return frozenset(cats) if cats else ALL_CATEGORIES


def _softmax(logits: np.ndarray) -> np.ndarray:
    """Row-wise softmax (numerically stable)."""
    shifted = logits - logits.max(axis=-1, keepdims=True)
    e = np.exp(shifted)
    return e / e.sum(axis=-1, keepdims=True)


@dataclass
class PIISpan:
    start: int
    end: int
    category: str
    text: str
    placeholder: str


class PrivacyEngine:
    def __init__(
        self,
        model_path: str | Path | None = None,
        use_coreml: bool = True,
        max_length: int = 4096,
        categories: frozenset[str] | None = None,
        confidence_threshold: float = 0.0,
        cache_size: int = 512,
    ):
        self.max_length = max_length
        self.categories = categories if categories is not None else ALL_CATEGORIES
        self.confidence_threshold = confidence_threshold
        self._cache: OrderedDict[str, list[PIISpan]] = OrderedDict()
        self._cache_size = cache_size
        self.encoding = tiktoken.get_encoding("o200k_base")

        if model_path is None:
            if ONNX_MODEL_PATH.exists():
                model_path = ONNX_MODEL_PATH
            else:
                model_path = download_model()

        providers = []
        if use_coreml and "CoreMLExecutionProvider" in ort.get_available_providers():
            providers.append("CoreMLExecutionProvider")
        providers.append("CPUExecutionProvider")

        try:
            self.session = ort.InferenceSession(str(model_path), providers=providers)
        except Exception:
            self.session = ort.InferenceSession(
                str(model_path), providers=["CPUExecutionProvider"]
            )
        self.active_providers = self.session.get_providers()

    def _tokenize(self, text: str) -> list[int]:
        return self.encoding.encode(text, allowed_special="all")

    def _decode_token_char_ranges(
        self, token_ids: list[int]
    ) -> tuple[str, list[int], list[int]]:
        byte_chunks = [
            self.encoding.decode_single_token_bytes(tid) for tid in token_ids
        ]
        all_bytes = b"".join(byte_chunks)
        decoded_text = all_bytes.decode("utf-8", errors="replace")

        char_byte_offsets = []
        offset = 0
        for ch in decoded_text:
            char_byte_offsets.append(offset)
            offset += len(ch.encode("utf-8"))

        char_starts = []
        char_ends = []
        byte_pos = 0
        for chunk in byte_chunks:
            chunk_start = byte_pos
            chunk_end = byte_pos + len(chunk)
            if chunk_start == 0:
                c_start = 0
            else:
                c_start = bisect.bisect_right(char_byte_offsets, chunk_start - 1)
            c_end = bisect.bisect_right(char_byte_offsets, chunk_end - 1)
            char_starts.append(c_start)
            char_ends.append(c_end)
            byte_pos = chunk_end

        return decoded_text, char_starts, char_ends

    def _run_inference(self, token_ids: list[int]) -> np.ndarray:
        input_array = np.array([token_ids], dtype=np.int64)
        attention_mask = np.ones_like(input_array)
        feeds = {"input_ids": input_array, "attention_mask": attention_mask}
        outputs = self.session.run(None, feeds)
        logits = outputs[0]
        return logits[0]

    def _decode_labels(self, logits: np.ndarray) -> list[int]:
        return logits.argmax(axis=-1).tolist()

    def _labels_to_spans(
        self, labels: list[int]
    ) -> list[tuple[int, int, int]]:
        """Convert token-level BIOES labels to (span_class_idx, tok_start, tok_end) spans."""
        spans = []
        current_span: Optional[int] = None
        current_start: int = 0

        for i, label_idx in enumerate(labels):
            boundary = TOKEN_BOUNDARY[label_idx]
            span_cls = TOKEN_TO_SPAN[label_idx]

            if boundary == "S":
                if current_span is not None:
                    spans.append((current_span, current_start, i))
                spans.append((span_cls, i, i + 1))
                current_span = None
            elif boundary == "B":
                if current_span is not None:
                    spans.append((current_span, current_start, i))
                current_span = span_cls
                current_start = i
            elif boundary == "I":
                if current_span is None or current_span != span_cls:
                    if current_span is not None:
                        spans.append((current_span, current_start, i))
                    current_span = span_cls
                    current_start = i
            elif boundary == "E":
                if current_span is not None and current_span == span_cls:
                    spans.append((current_span, current_start, i + 1))
                elif current_span is not None:
                    spans.append((current_span, current_start, i))
                    spans.append((span_cls, i, i + 1))
                else:
                    spans.append((span_cls, i, i + 1))
                current_span = None
            else:
                if current_span is not None:
                    spans.append((current_span, current_start, i))
                    current_span = None

        if current_span is not None:
            spans.append((current_span, current_start, len(labels)))

        return spans

    def detect(self, text: str) -> list[PIISpan]:
        # LRU cache lookup
        if self._cache_size > 0:
            text_hash = hashlib.sha256(text.encode()).hexdigest()[:16]
            if text_hash in self._cache:
                self._cache.move_to_end(text_hash)
                return list(self._cache[text_hash])
        else:
            text_hash = None

        token_ids = self._tokenize(text)
        if not token_ids:
            return []

        overlap = min(256, self.max_length // 4)
        stride = self.max_length - overlap

        num_tokens = len(token_ids)
        num_labels = len(TOKEN_LABELS)
        full_logits = np.zeros((num_tokens, num_labels), dtype=np.float32)
        counts = np.zeros(num_tokens, dtype=np.float32)

        for start in range(0, num_tokens, stride):
            end = min(start + self.max_length, num_tokens)
            chunk = token_ids[start:end]
            logits = self._run_inference(chunk)
            full_logits[start:end] += logits[: end - start]
            counts[start:end] += 1.0
            if end >= num_tokens:
                break

        counts = np.maximum(counts, 1.0)
        full_logits /= counts[:, None]

        labels = self._decode_labels(full_logits)

        # Per-token confidence (softmax probability of the predicted label)
        if self.confidence_threshold > 0:
            probs = _softmax(full_logits)
            token_conf = probs[np.arange(len(labels)), labels]
        else:
            token_conf = None

        token_spans = self._labels_to_spans(labels)

        _, char_starts, char_ends = self._decode_token_char_ranges(token_ids)

        pii_spans = []
        for span_cls, tok_start, tok_end in token_spans:
            if span_cls == 0:
                continue
            category = SPAN_CLASSES[span_cls]
            # Category whitelist filter
            if category not in self.categories:
                continue
            # Confidence threshold filter (min confidence across span tokens)
            if token_conf is not None:
                span_confidence = float(token_conf[tok_start:tok_end].min())
                if span_confidence < self.confidence_threshold:
                    continue
            c_start = char_starts[tok_start]
            c_end = char_ends[tok_end - 1]
            span_text = text[c_start:c_end]
            pii_spans.append(
                PIISpan(
                    start=c_start,
                    end=c_end,
                    category=category,
                    text=span_text,
                    placeholder=PLACEHOLDER_MAP[category],
                )
            )

        pii_spans.sort(key=lambda s: s.start)
        pii_spans = _trim_whitespace(pii_spans, text)
        result = _remove_overlaps(pii_spans)

        # Store in LRU cache
        if text_hash is not None:
            self._cache[text_hash] = result
            if len(self._cache) > self._cache_size:
                self._cache.popitem(last=False)

        return result

    def redact(self, text: str) -> tuple[str, list[PIISpan], dict[str, str]]:
        """Returns (redacted_text, detected_spans, reverse_mapping)."""
        spans = self.detect(text)
        if not spans:
            return text, [], {}

        reverse_map: dict[str, str] = {}
        counters: dict[str, int] = {}
        parts: list[str] = []
        last_end = 0

        for span in spans:
            parts.append(text[last_end : span.start])
            cat = span.category
            counters[cat] = counters.get(cat, 0) + 1
            tag = f"<{cat.upper()}_{counters[cat]}>"
            reverse_map[tag] = span.text
            parts.append(tag)
            last_end = span.end

        parts.append(text[last_end:])
        return "".join(parts), spans, reverse_map

    def deanonymize(self, text: str, reverse_map: dict[str, str]) -> str:
        result = text
        for tag, original in reverse_map.items():
            result = result.replace(tag, original)
        return result


def _trim_whitespace(spans: list[PIISpan], text: str) -> list[PIISpan]:
    trimmed = []
    for span in spans:
        s, e = span.start, span.end
        while s < e and text[s].isspace():
            s += 1
        while e > s and text[e - 1].isspace():
            e -= 1
        if s < e:
            trimmed.append(
                PIISpan(
                    start=s,
                    end=e,
                    category=span.category,
                    text=text[s:e],
                    placeholder=span.placeholder,
                )
            )
    return trimmed


def _remove_overlaps(spans: list[PIISpan]) -> list[PIISpan]:
    if not spans:
        return spans
    result = [spans[0]]
    for span in spans[1:]:
        if span.start >= result[-1].end:
            result.append(span)
    return result
