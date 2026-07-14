from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from typing import Any, BinaryIO

from .errors import CompileError
from .manifest import Manifest, manifest_schema
from .targets import TARGET_INSTRUCTIONS, Target


DEFAULT_MODEL = os.environ.get("PROMPT2EXE_MODEL", "gpt-5.6")
DEFAULT_API_BASE = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")

MODEL_INSTRUCTIONS = """\
You are a bytecode backend for small, standalone native programs. Translate
the user's program description into complete, directly executable machine
code for the requested target. Return only the requested structured manifest.

Runtime contract:
- The payload is entered directly as the executable's process entry point.
- No imported language runtime or library symbols are provided.
- Include all constants and data inside the payload.
- Use position-independent control flow and target-appropriate PC-relative data.
- Do not include an ELF, PE, or Mach-O header; shellcode_hex is code plus data.
- entry_offset is the byte offset of the first instruction in shellcode_hex.
- Check every instruction encoding, branch displacement, call displacement,
  PC-relative displacement, buffer length, ABI detail, and error path.
- Programs should report operational failures and exit nonzero.

shellcode_hex must contain only hexadecimal byte pairs; no 0x prefixes,
escapes, prose, comments, markdown, assembly source, or separators.
"""


def timeout_error(timeout: float) -> CompileError:
    suggested_timeout = max(1800.0, timeout * 2)
    return CompileError(
        f"API request timed out after {timeout:g} seconds. Complex reasoning can "
        f"take several minutes; retry with --timeout {suggested_timeout:g}."
    )


def extract_response_text(response: Any) -> str:
    if not isinstance(response, dict):
        raise CompileError("API response is not a JSON object")
    error = response.get("error")
    if isinstance(error, dict) and error.get("message"):
        raise CompileError(f"API response failed: {error['message']}")
    if response.get("status") == "incomplete":
        details = response.get("incomplete_details")
        reason = details.get("reason") if isinstance(details, dict) else "unknown reason"
        raise CompileError(f"API response is incomplete: {reason}")
    output_text = response.get("output_text")
    if isinstance(output_text, str) and output_text.strip():
        return output_text

    texts: list[str] = []
    for item in response.get("output", []):
        if not isinstance(item, dict) or item.get("type") != "message":
            continue
        for content in item.get("content", []):
            if not isinstance(content, dict):
                continue
            if content.get("type") == "refusal":
                refusal = content.get("refusal", "request refused")
                raise CompileError(f"model refused the request: {refusal}")
            if content.get("type") == "output_text" and isinstance(
                content.get("text"), str
            ):
                texts.append(content["text"])
    if not texts:
        raise CompileError("API response contains no output text")
    return "".join(texts)


def iter_sse_events(response: BinaryIO) -> Iterator[dict[str, Any]]:
    data_lines: list[str] = []
    for raw_line in response:
        line = raw_line.decode("utf-8", "replace").rstrip("\r\n")
        if not line:
            if data_lines:
                data = "\n".join(data_lines)
                data_lines.clear()
                if data != "[DONE]":
                    try:
                        event = json.loads(data)
                    except json.JSONDecodeError as exc:
                        raise CompileError(
                            f"API returned invalid streaming JSON: {exc}"
                        ) from exc
                    if not isinstance(event, dict):
                        raise CompileError("API streaming event is not a JSON object")
                    yield event
            continue
        if line.startswith(":"):
            continue
        field, separator, value = line.partition(":")
        if field == "data" and separator:
            data_lines.append(value[1:] if value.startswith(" ") else value)

    if data_lines:
        raise CompileError("API stream ended in the middle of an event")


def read_streaming_response(
    response: BinaryIO, on_reasoning_delta: Callable[[str], None]
) -> dict[str, Any]:
    result: dict[str, Any] | None = None
    for event in iter_sse_events(response):
        event_type = event.get("type")
        if event_type == "response.reasoning_summary_text.delta":
            delta = event.get("delta")
            if isinstance(delta, str):
                on_reasoning_delta(delta)
        elif event_type in {
            "response.completed",
            "response.failed",
            "response.incomplete",
        }:
            response_value = event.get("response")
            if isinstance(response_value, dict):
                result = response_value
        elif event_type == "error":
            message = event.get("message", "unknown streaming error")
            raise CompileError(f"API stream failed: {message}")
    if result is None:
        raise CompileError("API stream ended without a completed response")
    return result


def request_manifest(
    prompt: str,
    *,
    target: Target,
    api_key: str,
    model: str,
    api_base: str,
    timeout: float,
    reasoning_effort: str,
    max_payload: int,
    on_reasoning_delta: Callable[[str], None] | None = None,
) -> Manifest:
    body = {
        "model": model,
        "instructions": MODEL_INSTRUCTIONS + "\n" + TARGET_INSTRUCTIONS[target.manifest_name],
        "input": prompt,
        "store": False,
        "reasoning": {"effort": reasoning_effort},
        "max_output_tokens": 32768,
        "text": {
            "format": {
                "type": "json_schema",
                "name": "shellcode_manifest",
                "strict": True,
                "schema": manifest_schema(target),
            }
        },
    }
    if on_reasoning_delta is not None:
        body["stream"] = True
        body["reasoning"]["summary"] = "auto"
    request = urllib.request.Request(
        f"{api_base.rstrip('/')}/responses",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if on_reasoning_delta is None:
                result = json.load(response)
            else:
                result = read_streaming_response(response, on_reasoning_delta)
    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read().decode("utf-8", "replace")
        finally:
            exc.close()
        error_code = None
        try:
            parsed = json.loads(detail)
            error = parsed.get("error", {})
            if isinstance(error, dict):
                detail = error.get("message", detail)
                error_code = error.get("code") or error.get("type")
        except json.JSONDecodeError:
            pass
        if exc.code == 429 and (
            error_code == "insufficient_quota"
            or "exceeded your current quota" in detail.lower()
        ):
            detail += (
                "\n\nYour API key was accepted, but this API project has no "
                "available quota. ChatGPT subscriptions and API billing are "
                "separate. Set up API billing or add credits at:\n"
                "  https://platform.openai.com/settings/organization/billing/overview\n\n"
                "Billing changes can take a couple of minutes to become active."
            )
        raise CompileError(f"API request failed ({exc.code}): {detail}") from exc
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            raise timeout_error(timeout) from exc
        raise CompileError(f"API request failed: {exc.reason}") from exc
    except TimeoutError as exc:
        raise timeout_error(timeout) from exc
    except json.JSONDecodeError as exc:
        raise CompileError(f"API returned invalid JSON: {exc}") from exc

    text = extract_response_text(result)
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CompileError(f"model returned invalid JSON: {exc}") from exc
    return Manifest.from_mapping(
        value, max_payload=max_payload, expected_target=target
    )
