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


DEFAULT_MODEL = os.environ.get("PROMPT2EXE_MODEL", "gpt-5.6-sol")
DEFAULT_API_BASE = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")

MODEL_INSTRUCTIONS = """\
You are a meticulous bytecode backend for small, standalone native programs.
Translate the user's description into complete, directly executable machine
code for the requested target. Return only the requested structured manifest;
perform all planning and verification internally.

Correctness priorities:
- Correct execution, bounded memory access, deterministic cleanup, and useful
  failures take priority over visual richness, speed, or optional features.
- Never guess an instruction encoding, syscall number, ABI rule, kernel data
  structure layout, branch displacement, or API contract. Use only details you
  can account for exactly for the requested target.
- Prefer a smaller complete implementation over a larger fragile one. If the
  request is ambitious, simplify presentation or algorithms while preserving
  its core behavior, documented controls, error handling, and clean exit.

Runtime contract:
- The payload is entered directly as the executable's process entry point.
- No imported language runtime or library symbols are provided.
- The payload mapping is readable and executable but not writable. Embedded
  constants may live in the payload; all mutable state must use a bounded,
  explicitly initialized stack frame or memory obtained from the target OS.
- Do not assume any register, flag, stack byte, padding byte, or allocated byte
  is initially zero unless the target ABI explicitly guarantees it.
- Use position-independent control flow and target-appropriate PC-relative data.
- Do not include an ELF, PE, or Mach-O header. Return named raw byte chunks and
  relocation records using the manifest contract below.
- Establish a bounded stack frame without overwriting argc, argv, envp, return
  state, or embedded data. Maintain target-required stack alignment at every
  external API call and restore or discard the frame correctly before exit.
- Define an internal calling convention for helpers. Audit saved registers,
  argument registers, return registers, flag dependencies, and maximum stack
  depth on every call path.
- Use the target's baseline instruction set. Do not emit optional SIMD, crypto,
  bit-manipulation, or other extension instructions without runtime detection
  and a baseline fallback.

I/O and operating-system rules:
- Use only documented target syscalls or correctly resolved target APIs. Use
  kernel UAPI layouts, not similarly named C-library layouts.
- Check the exact target error convention. Retry only retryable failures such
  as interrupted operations, distinguish EOF from errors, handle partial I/O,
  and reject zero-progress loops.
- Every pointer and length passed to the OS must refer to initialized memory of
  at least that exact size. Every reported output length must match the bytes
  actually present, including escape sequences and trailing newlines.
- Once external state is changed, all normal, user-requested, EOF, and error
  exits must run cleanup in reverse order. Preserve the original failure status
  if cleanup also fails. Diagnostics go to standard error and failures exit
  nonzero.

Interactive terminal rules, when applicable:
- Verify required descriptors are terminals. Save the complete original
  terminal state before changing it and restore that exact state on every exit
  after the change. Treat Ctrl-C and the requested quit key as cleanup paths.
- Configure input deliberately. Account for blocking versus nonblocking reads,
  EOF, EINTR/EAGAIN, and escape sequences split across multiple reads.
- Query rows and columns using the exact target structure layout. Validate
  minimum dimensions, cap unreasonable dimensions, handle resize safely, and
  clamp every coordinate before indexing or multiplying it.
- Do not size a stack frame or framebuffer directly from untrusted terminal
  dimensions. Use a fixed maximum, checked OS allocation, or bounded streaming
  rendering. Check all size arithmetic for overflow.
- Use a monotonic target clock for frame pacing. Fully initialize timeout
  structures, normalize their fields, and handle interrupted sleeps.
- Keep terminal escape sequences complete, restore cursor visibility and screen
  mode, and never leave the terminal altered after a handled exit.

Relocatable manifest contract:
- chunks are concatenated in array order. Give every basic-block entry, helper,
  branch destination, and distinct data object its own uniquely named chunk.
  Mark instructions as code and constants as data. On Arm, the linker pads the
  start of every chunk to four-byte alignment.
- entry names the code chunk containing the process entry instruction.
- Never encode a PC-relative branch, call, or data-reference displacement
  yourself. Emit a supported zero-immediate instruction form and add a fixup.
- A fixup's source names a dedicated code chunk whose relocation field is at
  the very end of that chunk. A source chunk may have exactly one fixup; split
  the bytes immediately after every relocation field into another chunk.
- On x86-64, use x86_rel32 for E8 calls, E9 jumps, and 0F 8x conditional jumps,
  always followed by four zero placeholder bytes. Do not use short branches.
  Use x86_rip_rel32 for an instruction ending in a RIP-relative ModRM byte and
  four zero displacement bytes. Choose forms with no immediate after disp32.
- On AArch64, use aarch64_branch26 for B/BL, aarch64_branch19 for B.cond and
  CBZ/CBNZ, aarch64_branch14 for TBZ/TBNZ, aarch64_adr21 for ADR, and
  aarch64_literal19 for load-literal instructions. Leave all relocated
  immediate bits zero. Do not use ADRP.
- On 32-bit Arm, use arm_branch24 for ARM-state B/BL and arm_literal12 for an
  immediate LDR with Rn=PC. Leave relocated immediate bits zero.
- Every fixup target is the exact start of a named chunk. Reorder or split
  chunks instead of adding a numeric offset. The linker validates opcode forms,
  alignment, placeholder bits, signed ranges, and target existence, then
  computes all displacements from the final layout.

Mandatory internal construction and audit:
1. Design a byte-accurate memory map for code, read-only data, mutable state,
   buffers, and stack slots. Prove each access stays within its region.
2. Plan symbolic labels and exact instruction sizes before encoding. Express
   every relative reference as a fixup; do not duplicate the linker's work.
3. Decode each code chunk independently. Verify every instruction boundary,
   fallthrough, embedded-data boundary, and reachable return. Confirm each
   relative instruction ends exactly where its source chunk ends and targets
   the intended code or data chunk.
4. Audit arithmetic hazards: division inputs and high halves, zero divisors,
   signed versus unsigned comparisons, shift ranges, truncation, overflow, and
   loop termination.
5. Trace success, boundary input, EOF, retryable interruption, short I/O, and
   one failure path. Confirm cleanup and the final exit status for each trace.
6. Recheck every instruction byte, immediate, displacement, buffer length,
   syscall/API identifier, ABI detail, and error path after the final edit.

Each chunk hex value must contain only hexadecimal byte pairs; no 0x prefixes,
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
    manifest = Manifest.from_mapping(
        value, max_payload=max_payload, expected_target=target
    )
    if manifest.entry is None:
        raise CompileError(
            "model returned a legacy flat manifest; relocatable output required"
        )
    return manifest
