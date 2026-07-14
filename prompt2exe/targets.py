from __future__ import annotations

from dataclasses import dataclass

from .errors import CompileError


@dataclass(frozen=True)
class Target:
    os_name: str
    architecture: str
    manifest_name: str
    binary_format: str
    bits: int
    machine: int
    default_base: int


TARGETS = {
    ("linux", "x86_64"): Target(
        "linux", "x86_64", "x86_64-linux", "elf64", 64, 62, 0x400000
    ),
    ("linux", "aarch64"): Target(
        "linux", "aarch64", "aarch64-linux", "elf64", 64, 183, 0x400000
    ),
    ("linux", "arm"): Target(
        "linux", "arm", "arm-linux", "elf32", 32, 40, 0x10000
    ),
    ("windows", "x86_64"): Target(
        "windows", "x86_64", "x86_64-windows", "pe32+", 64, 0x8664, 0x140000000
    ),
    ("macos", "x86_64"): Target(
        "macos", "x86_64", "x86_64-macos", "macho64", 64, 0x01000007, 0x100000000
    ),
    ("macos", "aarch64"): Target(
        "macos", "aarch64", "aarch64-macos", "macho64", 64, 0x0100000C, 0x100000000
    ),
}
TARGETS_BY_MANIFEST = {target.manifest_name: target for target in TARGETS.values()}

OS_ALIASES = {
    "linux": "linux",
    "windows": "windows",
    "win32": "windows",
    "macos": "macos",
    "mac": "macos",
    "darwin": "macos",
}
ARCH_ALIASES = {
    "x86_64": "x86_64",
    "x64": "x86_64",
    "amd64": "x86_64",
    "aarch64": "aarch64",
    "arm64": "aarch64",
    "arm": "arm",
    "arm32": "arm",
    "aarch32": "arm",
}

TARGET_INSTRUCTIONS = {
    "x86_64-linux": """\
Target: Linux x86-64, little-endian. Use the Linux x86-64 syscall ABI: syscall
number in RAX, arguments in RDI, RSI, RDX, R10, R8, R9, and SYSCALL. At entry,
RSP contains argc, argv, and envp; other registers are undefined. Use
RIP-relative addressing for embedded data.
""",
    "aarch64-linux": """\
Target: Linux AArch64, little-endian A64 instructions. Use the Linux AArch64
syscall ABI: syscall number in X8, arguments in X0 through X5, and SVC #0. At
entry, SP contains argc, argv, and envp; other registers are undefined. Keep
instructions 4-byte aligned and use ADR/ADRP or literal addressing correctly.
""",
    "arm-linux": """\
Target: Linux 32-bit Arm EABI, little-endian ARM instruction state (not Thumb).
Use R7 for the syscall number, R0 through R6 for arguments, and SVC #0. At
entry, SP contains argc, argv, and envp; other registers are undefined. Keep
instructions 4-byte aligned and account for the ARM PC pipeline in data access.
""",
    "x86_64-windows": """\
Target: 64-bit Windows x64 using the Microsoft x64 ABI. The PE has no import
table. Do not use unstable hard-coded Windows syscall numbers: resolve required
Win32 APIs from the PEB and module export tables inside the payload. Preserve
nonvolatile registers, maintain 16-byte stack alignment, reserve 32 bytes of
shadow space before calls, and terminate through a resolved ExitProcess. Use
RIP-relative addressing for embedded data.
""",
    "x86_64-macos": """\
Target: macOS x86-64 using the Darwin syscall ABI and position-independent
code. The Mach-O image has no imported symbols. For BSD syscalls, place the
0x02000000 syscall class plus syscall number in RAX, arguments in RDI, RSI,
RDX, R10, R8, and R9, then use SYSCALL. Use RIP-relative embedded data and
terminate with the Darwin exit syscall.
""",
    "aarch64-macos": """\
Target: macOS Apple Silicon using little-endian AArch64 instructions and
position-independent code. The Mach-O image has no imported symbols. Use the
Darwin ARM64 BSD syscall convention with the syscall number in X16, arguments
in X0 onward, and SVC #0x80. Keep instructions 4-byte aligned and terminate
with the Darwin exit syscall.
""",
}


def resolve_target(
    os_name: str | None, architecture: str | None, *, use_defaults: bool = True
) -> Target | None:
    if os_name is None and architecture is None and not use_defaults:
        return None
    raw_os = os_name or "linux"
    raw_arch = architecture or "x86_64"
    normalized_os = OS_ALIASES.get(raw_os.lower())
    normalized_arch = ARCH_ALIASES.get(raw_arch.lower())
    if normalized_os is None:
        raise CompileError(f"unsupported operating system: {raw_os}")
    if normalized_arch is None:
        raise CompileError(f"unsupported architecture: {raw_arch}")
    target = TARGETS.get((normalized_os, normalized_arch))
    if target is None:
        supported = ", ".join(
            f"{item.os_name}/{item.architecture}" for item in TARGETS.values()
        )
        raise CompileError(
            f"unsupported target {normalized_os}/{normalized_arch}; supported: {supported}"
        )
    return target
