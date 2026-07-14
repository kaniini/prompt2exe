from __future__ import annotations

from ..errors import CompileError
from ..manifest import Manifest
from .elf import build_elf
from .macho import build_macho
from .pe import build_pe


def build_executable(manifest: Manifest, base_address: int | None = None) -> bytes:
    if manifest.target.os_name == "linux":
        return build_elf(manifest, base_address)
    if manifest.target.os_name == "windows":
        return build_pe(manifest, base_address)
    if manifest.target.os_name == "macos":
        return build_macho(manifest, base_address)
    raise CompileError(f"unsupported operating system: {manifest.target.os_name}")


__all__ = ["build_elf", "build_executable", "build_macho", "build_pe"]
