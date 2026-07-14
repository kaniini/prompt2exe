from __future__ import annotations

import struct

from ..errors import CompileError
from ..manifest import Manifest
from .common import align_up, validate_base_address


PE_FILE_ALIGNMENT = 0x200
PE_SECTION_ALIGNMENT = 0x1000
PE_HEADERS_SIZE = 0x200
PE_TEXT_RVA = 0x1000


def build_pe(manifest: Manifest, base_address: int | None = None) -> bytes:
    target = manifest.target
    if target.binary_format != "pe32+":
        raise CompileError("PE32+ output requires a supported Windows target")
    if base_address is None:
        base_address = target.default_base
    validate_base_address(base_address, target)

    virtual_size = len(manifest.shellcode)
    raw_size = align_up(virtual_size, PE_FILE_ALIGNMENT)
    size_of_image = align_up(PE_TEXT_RVA + virtual_size, PE_SECTION_ALIGNMENT)
    entry_rva = PE_TEXT_RVA + manifest.entry_offset

    dos_header = bytearray(0x80)
    dos_header[:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 0x80)
    coff_header = struct.pack(
        "<HHIIIHH", target.machine, 1, 0, 0, 0, 0xF0, 0x0022
    )
    optional_header = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B,
        0,
        0,
        raw_size,
        0,
        0,
        entry_rva,
        PE_TEXT_RVA,
        base_address,
        PE_SECTION_ALIGNMENT,
        PE_FILE_ALIGNMENT,
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        size_of_image,
        PE_HEADERS_SIZE,
        0,
        3,
        0x0100,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    ) + b"\x00" * 128
    section_header = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        virtual_size,
        PE_TEXT_RVA,
        raw_size,
        PE_HEADERS_SIZE,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    headers = bytes(dos_header) + b"PE\x00\x00" + coff_header + optional_header
    headers += section_header
    if len(headers) > PE_HEADERS_SIZE:
        raise AssertionError("PE headers exceed file alignment")
    headers += b"\x00" * (PE_HEADERS_SIZE - len(headers))
    return headers + manifest.shellcode + b"\x00" * (raw_size - virtual_size)
