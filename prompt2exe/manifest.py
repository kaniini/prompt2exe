from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .errors import CompileError
from .linker import FIXUP_KINDS, Chunk, Fixup, link_chunks
from .targets import TARGETS_BY_MANIFEST, Target


DEFAULT_MAX_PAYLOAD = 64 * 1024
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
LABEL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
LEGACY_FIELDS = {"architecture", "shellcode_hex", "entry_offset", "description"}
RELOCATABLE_FIELDS = {"architecture", "chunks", "entry", "fixups", "description"}


def manifest_schema(target: Target) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "architecture": {"type": "string", "enum": [target.manifest_name]},
            "chunks": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "properties": {
                        "label": {"type": "string", "pattern": LABEL_RE.pattern},
                        "kind": {"type": "string", "enum": ["code", "data"]},
                        "hex": {"type": "string"},
                    },
                    "required": ["label", "kind", "hex"],
                    "additionalProperties": False,
                },
            },
            "entry": {"type": "string", "pattern": LABEL_RE.pattern},
            "fixups": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "source": {"type": "string", "pattern": LABEL_RE.pattern},
                        "kind": {
                            "type": "string",
                            "enum": list(FIXUP_KINDS[target.architecture]),
                        },
                        "target": {"type": "string", "pattern": LABEL_RE.pattern},
                    },
                    "required": ["source", "kind", "target"],
                    "additionalProperties": False,
                },
            },
            "description": {"type": "string"},
        },
        "required": ["architecture", "chunks", "entry", "fixups", "description"],
        "additionalProperties": False,
    }


def _read_hex(raw_hex: Any, field: str) -> bytes:
    if not isinstance(raw_hex, str):
        raise CompileError(f"{field} must be a string")
    compact_hex = "".join(raw_hex.split())
    if not compact_hex:
        raise CompileError(f"{field} must not be empty")
    if len(compact_hex) % 2:
        raise CompileError(f"{field} must contain complete byte pairs")
    if not HEX_RE.fullmatch(compact_hex):
        raise CompileError(f"{field} contains non-hexadecimal characters")
    return bytes.fromhex(compact_hex)


def _read_target(value: dict[str, Any], expected_target: Target | None) -> Target:
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
    return target


def _check_fields(value: dict[str, Any], expected: set[str]) -> None:
    missing = expected - value.keys()
    extra = value.keys() - expected
    if missing:
        raise CompileError(f"manifest is missing: {', '.join(sorted(missing))}")
    if extra:
        raise CompileError(f"manifest has unknown fields: {', '.join(sorted(extra))}")


def _check_description(value: Any) -> str:
    if not isinstance(value, str):
        raise CompileError("description must be a string")
    if len(value) > 4096:
        raise CompileError("description is unreasonably long")
    return value


def _check_payload_header(shellcode: bytes) -> None:
    if shellcode.startswith((b"\x7fELF", b"MZ")):
        raise CompileError("payload already contains an executable header")
    if shellcode.startswith(b"\xcf\xfa\xed\xfe"):
        raise CompileError("payload already contains a Mach-O header")


@dataclass(frozen=True)
class Manifest:
    target: Target
    shellcode: bytes
    entry_offset: int
    description: str
    chunks: tuple[Chunk, ...] = ()
    fixups: tuple[Fixup, ...] = ()
    entry: str | None = None

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
        if "chunks" in value or "fixups" in value or "entry" in value:
            return cls._from_relocatable(value, max_payload, expected_target)

        _check_fields(value, LEGACY_FIELDS)
        target = _read_target(value, expected_target)
        shellcode = _read_hex(value["shellcode_hex"], "shellcode_hex")
        if len(shellcode) > max_payload:
            raise CompileError(
                f"payload is {len(shellcode)} bytes; limit is {max_payload} bytes"
            )
        _check_payload_header(shellcode)
        entry_offset = value["entry_offset"]
        if isinstance(entry_offset, bool) or not isinstance(entry_offset, int):
            raise CompileError("entry_offset must be an integer")
        if not 0 <= entry_offset < len(shellcode):
            raise CompileError("entry_offset must point inside the payload")
        if target.architecture in {"aarch64", "arm"} and entry_offset % 4:
            raise CompileError("Arm entry_offset must be 4-byte aligned")
        description = _check_description(value["description"])
        return cls(target, shellcode, entry_offset, description)

    @classmethod
    def _from_relocatable(
        cls,
        value: dict[str, Any],
        max_payload: int,
        expected_target: Target | None,
    ) -> "Manifest":
        _check_fields(value, RELOCATABLE_FIELDS)
        target = _read_target(value, expected_target)
        raw_chunks = value["chunks"]
        if not isinstance(raw_chunks, list) or not raw_chunks:
            raise CompileError("chunks must be a non-empty array")
        chunks: list[Chunk] = []
        raw_size = 0
        for index, item in enumerate(raw_chunks):
            if not isinstance(item, dict):
                raise CompileError(f"chunks[{index}] must be an object")
            _check_fields(item, {"label", "kind", "hex"})
            label = item["label"]
            if not isinstance(label, str) or not LABEL_RE.fullmatch(label):
                raise CompileError(f"chunks[{index}].label is invalid")
            kind = item["kind"]
            if kind not in {"code", "data"}:
                raise CompileError(f"chunks[{index}].kind must be code or data")
            data = _read_hex(item["hex"], f"chunks[{index}].hex")
            if kind == "code" and target.architecture in {"aarch64", "arm"}:
                if len(data) % 4:
                    raise CompileError(f"Arm code chunk {label} is not word-aligned")
            chunks.append(Chunk(label, kind, data))
            raw_size += len(data)
            if raw_size > max_payload:
                raise CompileError(
                    f"unlinked payload exceeds the {max_payload}-byte limit"
                )

        entry = value["entry"]
        if not isinstance(entry, str) or not LABEL_RE.fullmatch(entry):
            raise CompileError("entry must be a valid chunk label")
        raw_fixups = value["fixups"]
        if not isinstance(raw_fixups, list):
            raise CompileError("fixups must be an array")
        fixups: list[Fixup] = []
        for index, item in enumerate(raw_fixups):
            if not isinstance(item, dict):
                raise CompileError(f"fixups[{index}] must be an object")
            _check_fields(item, {"source", "kind", "target"})
            fields = (item["source"], item["kind"], item["target"])
            if not all(isinstance(field, str) for field in fields):
                raise CompileError(f"fixups[{index}] fields must be strings")
            source, fixup_kind, fixup_target = fields
            if not LABEL_RE.fullmatch(source) or not LABEL_RE.fullmatch(fixup_target):
                raise CompileError(f"fixups[{index}] has an invalid label")
            fixups.append(Fixup(source, fixup_kind, fixup_target))

        shellcode, entry_offset = link_chunks(
            target, tuple(chunks), tuple(fixups), entry, max_payload
        )
        _check_payload_header(shellcode)
        description = _check_description(value["description"])
        return cls(
            target,
            shellcode,
            entry_offset,
            description,
            tuple(chunks),
            tuple(fixups),
            entry,
        )

    def as_json(self) -> dict[str, Any]:
        if self.entry is not None:
            return {
                "architecture": self.architecture,
                "chunks": [
                    {"label": chunk.label, "kind": chunk.kind, "hex": chunk.data.hex()}
                    for chunk in self.chunks
                ],
                "entry": self.entry,
                "fixups": [
                    {
                        "source": fixup.source,
                        "kind": fixup.kind,
                        "target": fixup.target,
                    }
                    for fixup in self.fixups
                ],
                "description": self.description,
            }
        return {
            "architecture": self.architecture,
            "shellcode_hex": self.shellcode.hex(),
            "entry_offset": self.entry_offset,
            "description": self.description,
        }
