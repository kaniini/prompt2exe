from __future__ import annotations

import struct

from ..errors import CompileError
from ..manifest import Manifest
from .common import align_up, validate_base_address


MACHO_PAYLOAD_OFFSET = 0x1000


def build_macho(manifest: Manifest, base_address: int | None = None) -> bytes:
    target = manifest.target
    if target.binary_format != "macho64":
        raise CompileError("Mach-O output requires a supported macOS target")
    if base_address is None:
        base_address = target.default_base
    validate_base_address(base_address, target)

    file_size = MACHO_PAYLOAD_OFFSET + len(manifest.shellcode)
    cpu_subtype = 3 if target.architecture == "x86_64" else 0
    pagezero = struct.pack(
        "<II16sQQQQiiII",
        0x19,
        72,
        b"__PAGEZERO".ljust(16, b"\x00"),
        0,
        base_address,
        0,
        0,
        0,
        0,
        0,
        0,
    )
    text_segment = struct.pack(
        "<II16sQQQQiiII",
        0x19,
        152,
        b"__TEXT".ljust(16, b"\x00"),
        base_address,
        align_up(file_size, 0x1000),
        0,
        file_size,
        7,
        5,
        1,
        0,
    )
    text_section = struct.pack(
        "<16s16sQQIIIIIIII",
        b"__text".ljust(16, b"\x00"),
        b"__TEXT".ljust(16, b"\x00"),
        base_address + MACHO_PAYLOAD_OFFSET,
        len(manifest.shellcode),
        MACHO_PAYLOAD_OFFSET,
        2,
        0,
        0,
        0x80000400,
        0,
        0,
        0,
    )
    dyld_path = b"/usr/lib/dyld\x00"
    load_dyld = struct.pack("<III", 0x0E, 32, 12) + dyld_path
    load_dyld += b"\x00" * (32 - len(load_dyld))
    main_command = struct.pack(
        "<IIQQ",
        0x80000028,
        24,
        MACHO_PAYLOAD_OFFSET + manifest.entry_offset,
        0,
    )
    build_version = struct.pack(
        "<IIIIII", 0x32, 24, 1, 0x000B0000, 0x000B0000, 0
    )
    commands = (
        pagezero
        + text_segment
        + text_section
        + load_dyld
        + main_command
        + build_version
    )
    header = struct.pack(
        "<IIIIIIII",
        0xFEEDFACF,
        target.machine,
        cpu_subtype,
        2,
        5,
        len(commands),
        0x00200085,
        0,
    )
    if len(header) + len(commands) > MACHO_PAYLOAD_OFFSET:
        raise AssertionError("Mach-O load commands exceed payload offset")
    padding = b"\x00" * (MACHO_PAYLOAD_OFFSET - len(header) - len(commands))
    return header + commands + padding + manifest.shellcode
