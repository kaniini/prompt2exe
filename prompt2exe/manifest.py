from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .errors import CompileError
from .targets import TARGETS_BY_MANIFEST, Target


DEFAULT_MAX_PAYLOAD = 64 * 1024
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def manifest_schema(target: Target) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "architecture": {"type": "string", "enum": [target.manifest_name]},
            "shellcode_hex": {"type": "string"},
            "entry_offset": {"type": "integer", "minimum": 0},
            "description": {"type": "string"},
        },
        "required": [
            "architecture",
            "shellcode_hex",
            "entry_offset",
            "description",
        ],
        "additionalProperties": False,
    }


@dataclass(frozen=True)
class Manifest:
    target: Target
    shellcode: bytes
    entry_offset: int
    description: str

    @property
    def architecture(self) -> str:
        return self.target.manifest_name

    @classmethod
    def from_mapping(
        cls,
        value: Any,
        *,
        max_payload: int = DEFAULT_MAX_PAYLOAD,
        expected_target: Target | None = None,
    ) -> "Manifest":
        if not isinstance(value, dict):
            raise CompileError("manifest must be a JSON object")
        expected = {"architecture", "shellcode_hex", "entry_offset", "description"}
        missing = expected - value.keys()
        extra = value.keys() - expected
        if missing:
            raise CompileError(f"manifest is missing: {', '.join(sorted(missing))}")
        if extra:
            raise CompileError(f"manifest has unknown fields: {', '.join(sorted(extra))}")

        architecture = value["architecture"]
        if not isinstance(architecture, str):
            raise CompileError("architecture must be a string")
        target = TARGETS_BY_MANIFEST.get(architecture)
        if target is None:
            supported = ", ".join(TARGETS_BY_MANIFEST)
            raise CompileError(f"unsupported manifest architecture; supported: {supported}")
        if expected_target is not None and target != expected_target:
            raise CompileError(
                f"manifest target {target.manifest_name} does not match requested "
                f"target {expected_target.manifest_name}"
            )

        raw_hex = value["shellcode_hex"]
        if not isinstance(raw_hex, str):
            raise CompileError("shellcode_hex must be a string")
        compact_hex = "".join(raw_hex.split())
        if not compact_hex:
            raise CompileError("shellcode_hex must not be empty")
        if len(compact_hex) % 2:
            raise CompileError("shellcode_hex must contain complete byte pairs")
        if not HEX_RE.fullmatch(compact_hex):
            raise CompileError("shellcode_hex contains non-hexadecimal characters")
        shellcode = bytes.fromhex(compact_hex)
        if len(shellcode) > max_payload:
            raise CompileError(
                f"payload is {len(shellcode)} bytes; limit is {max_payload} bytes"
            )
        if shellcode.startswith((b"\x7fELF", b"MZ")):
            raise CompileError("payload already contains an executable header")
        if shellcode.startswith(b"\xcf\xfa\xed\xfe"):
            raise CompileError("payload already contains a Mach-O header")

        entry_offset = value["entry_offset"]
        if isinstance(entry_offset, bool) or not isinstance(entry_offset, int):
            raise CompileError("entry_offset must be an integer")
        if not 0 <= entry_offset < len(shellcode):
            raise CompileError("entry_offset must point inside the payload")
        if target.architecture in {"aarch64", "arm"} and entry_offset % 4:
            raise CompileError("Arm entry_offset must be 4-byte aligned")

        description = value["description"]
        if not isinstance(description, str):
            raise CompileError("description must be a string")
        if len(description) > 4096:
            raise CompileError("description is unreasonably long")
        return cls(target, shellcode, entry_offset, description)

    def as_json(self) -> dict[str, Any]:
        return {
            "architecture": self.architecture,
            "shellcode_hex": self.shellcode.hex(),
            "entry_offset": self.entry_offset,
            "description": self.description,
        }
