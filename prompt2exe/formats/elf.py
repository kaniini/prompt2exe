from __future__ import annotations

import struct

from ..errors import CompileError
from ..manifest import Manifest
from .common import validate_base_address


ELF64_HEADER_SIZE = 64
ELF64_PROGRAM_HEADER_SIZE = 56
ELF64_PAYLOAD_OFFSET = ELF64_HEADER_SIZE + ELF64_PROGRAM_HEADER_SIZE
ELF32_HEADER_SIZE = 52
ELF32_PROGRAM_HEADER_SIZE = 32
ELF32_PAYLOAD_OFFSET = ELF32_HEADER_SIZE + ELF32_PROGRAM_HEADER_SIZE


def build_elf(manifest: Manifest, base_address: int | None = None) -> bytes:
    target = manifest.target
    if target.os_name != "linux":
        raise CompileError("ELF output requires a Linux target")
    if base_address is None:
        base_address = target.default_base
    validate_base_address(base_address, target)

    if target.binary_format == "elf64":
        file_size = ELF64_PAYLOAD_OFFSET + len(manifest.shellcode)
        entry_address = base_address + ELF64_PAYLOAD_OFFSET + manifest.entry_offset
        if entry_address > 0xFFFFFFFFFFFFFFFF:
            raise CompileError("entry address overflows ELF64")
        ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
        elf_header = struct.pack(
            "<16sHHIQQQIHHHHHH",
            ident,
            2,
            target.machine,
            1,
            entry_address,
            ELF64_HEADER_SIZE,
            0,
            0,
            ELF64_HEADER_SIZE,
            ELF64_PROGRAM_HEADER_SIZE,
            1,
            0,
            0,
            0,
        )
        program_header = struct.pack(
            "<IIQQQQQQ",
            1,
            5,
            0,
            base_address,
            base_address,
            file_size,
            file_size,
            0x1000,
        )
        return elf_header + program_header + manifest.shellcode

    if target.binary_format != "elf32":
        raise CompileError(f"unsupported Linux format: {target.binary_format}")
    file_size = ELF32_PAYLOAD_OFFSET + len(manifest.shellcode)
    entry_address = base_address + ELF32_PAYLOAD_OFFSET + manifest.entry_offset
    if entry_address > 0xFFFFFFFF:
        raise CompileError("entry address overflows ELF32")
    ident = b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 8
    elf_header = struct.pack(
        "<16sHHIIIIIHHHHHH",
        ident,
        2,
        target.machine,
        1,
        entry_address,
        ELF32_HEADER_SIZE,
        0,
        0x05000000,
        ELF32_HEADER_SIZE,
        ELF32_PROGRAM_HEADER_SIZE,
        1,
        0,
        0,
        0,
    )
    program_header = struct.pack(
        "<IIIIIIII",
        1,
        0,
        base_address,
        base_address,
        file_size,
        file_size,
        5,
        0x1000,
    )
    return elf_header + program_header + manifest.shellcode
