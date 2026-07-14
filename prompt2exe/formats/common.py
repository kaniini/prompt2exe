from __future__ import annotations

from ..errors import CompileError
from ..targets import Target


def align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def validate_base_address(base_address: int, target: Target) -> None:
    if not isinstance(base_address, int) or isinstance(base_address, bool):
        raise CompileError("base address must be an integer")
    if base_address < 0 or base_address > 0xFFFFFFFFFFFFFFFF:
        raise CompileError("base address is outside the 64-bit address range")
    if target.bits == 32 and base_address > 0xFFFFFFFF:
        raise CompileError("base address is outside the 32-bit address range")
    alignment = 0x10000 if target.binary_format == "pe32+" else 0x1000
    if base_address % alignment:
        raise CompileError(f"base address must be aligned to {alignment:#x}")
