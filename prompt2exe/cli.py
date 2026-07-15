from __future__ import annotations

import argparse
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import NoReturn

from .api import DEFAULT_API_BASE, DEFAULT_MODEL, request_manifest
from .errors import CompileError
from .flow import TerminalFlowWriter
from .formats import build_executable
from .manifest import DEFAULT_MAX_PAYLOAD, Manifest
from .output import load_manifest, write_executable, write_manifest
from .review import build_review_prompt
from .targets import ARCH_ALIASES, Target, resolve_target
from .throbber import Throbber


DEFAULT_TIMEOUT = 900.0


def parse_int(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer: {value}") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="prompt2exe",
        description="Compile a prompt into a minimal native ELF, PE, or Mach-O executable"
    )
    parser.add_argument("prompt", nargs="?", help="program description")
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument(
        "--os", dest="target_os", help="target OS: linux, windows, or macos"
    )
    parser.add_argument(
        "--arch", help="target architecture: x86_64, aarch64, or arm"
    )
    parser.add_argument("--prompt-file", type=Path, help="read the prompt from a file")
    parser.add_argument(
        "--manifest", type=Path, help="compile an existing manifest without an API call"
    )
    parser.add_argument("--manifest-out", type=Path, help="save the validated manifest")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--api-base", default=DEFAULT_API_BASE)
    parser.add_argument(
        "--reasoning",
        choices=("none", "minimal", "low", "medium", "high", "xhigh"),
        default="high",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="API socket timeout in seconds (default: 900)",
    )
    parser.add_argument("--max-payload", type=parse_int, default=DEFAULT_MAX_PAYLOAD)
    parser.add_argument("--base-address", type=parse_int)
    parser.add_argument(
        "--verify-passes",
        type=int,
        default=1,
        help="independent model verification passes (default: 1; maximum: 3)",
    )
    parser.add_argument("--force", action="store_true", help="replace existing outputs")
    parser.add_argument(
        "--run", action="store_true", help="execute the generated file after writing it"
    )
    parser.add_argument(
        "--arg", action="append", default=[], help="argument passed to the generated file"
    )
    parser.add_argument(
        "--quiet", action="store_true", help="suppress status output and the throbber"
    )
    return parser


def resolve_prompt(args: argparse.Namespace) -> str:
    sources = sum(
        (args.prompt is not None, args.prompt_file is not None, args.manifest is not None)
    )
    if sources != 1:
        raise CompileError("provide exactly one of PROMPT, --prompt-file, or --manifest")
    if args.prompt_file is not None:
        try:
            prompt = args.prompt_file.read_text(encoding="utf-8")
        except OSError as exc:
            raise CompileError(
                f"cannot read prompt file {args.prompt_file}: {exc.strerror}"
            ) from exc
    else:
        prompt = args.prompt
    if prompt is None or not prompt.strip():
        raise CompileError("prompt must not be empty")
    return prompt.strip()


def host_can_run(target: Target) -> bool:
    if sys.platform.startswith("linux"):
        host_os = "linux"
    elif sys.platform == "win32":
        host_os = "windows"
    elif sys.platform == "darwin":
        host_os = "macos"
    else:
        return False
    machine = platform.machine().lower()
    host_arch = ARCH_ALIASES.get(machine)
    if host_arch is None and machine.startswith("armv"):
        host_arch = "arm"
    return host_os == target.os_name and host_arch == target.architecture


def fail(message: str) -> NoReturn:
    print(f"prompt2exe: error: {message}", file=sys.stderr)
    raise SystemExit(1)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.max_payload <= 0:
            raise CompileError("--max-payload must be positive")
        if args.timeout <= 0:
            raise CompileError("--timeout must be positive")
        if not 0 <= args.verify_passes <= 3:
            raise CompileError("--verify-passes must be between 0 and 3")
        if args.manifest is not None:
            if args.prompt is not None or args.prompt_file is not None:
                raise CompileError(
                    "--manifest cannot be combined with a prompt or --prompt-file"
                )
            manifest = load_manifest(args.manifest, args.max_payload)
            if args.target_os is not None or args.arch is not None:
                constrained_target = resolve_target(
                    args.target_os or manifest.target.os_name,
                    args.arch or manifest.target.architecture,
                )
                if constrained_target != manifest.target:
                    raise CompileError(
                        f"manifest target {manifest.architecture} does not match "
                        f"requested target {constrained_target.manifest_name}"
                    )
        else:
            target = resolve_target(args.target_os, args.arch)
            assert target is not None
            prompt = resolve_prompt(args)
            api_key = os.environ.get("OPENAI_API_KEY")
            if not api_key:
                raise CompileError(
                    "OPENAI_API_KEY is not set.\n\n"
                    "Create an API key at:\n"
                    "  https://platform.openai.com/api-keys\n\n"
                    "Then export it in this shell and run the command again:\n"
                    "  export OPENAI_API_KEY='your-api-key'\n\n"
                    "Keep the key secret; do not commit or share it."
                )
            def model_pass(model_prompt: str, status: str) -> Manifest:
                with Throbber(
                    status,
                    stream=sys.stderr,
                    enabled=not args.quiet and sys.stderr.isatty(),
                ) as throbber:
                    reasoning_output = TerminalFlowWriter(
                        stream=sys.stderr, prefix="progress: "
                    )

                    def show_reasoning(delta: str) -> None:
                        throbber.stop()
                        reasoning_output.write(delta)

                    try:
                        return request_manifest(
                            model_prompt,
                            target=target,
                            api_key=api_key,
                            model=args.model,
                            api_base=args.api_base,
                            timeout=args.timeout,
                            reasoning_effort=args.reasoning,
                            max_payload=args.max_payload,
                            on_reasoning_delta=None if args.quiet else show_reasoning,
                        )
                    finally:
                        reasoning_output.finish()

            manifest = model_pass(prompt, "Generating")
            for pass_number in range(1, args.verify_passes + 1):
                review_prompt = build_review_prompt(prompt, manifest, pass_number)
                manifest = model_pass(
                    review_prompt, f"Verifying {pass_number}/{args.verify_passes}"
                )

        output = args.output
        if output is None:
            output = Path("a.exe" if manifest.target.os_name == "windows" else "a.out")
        if args.manifest_out is not None:
            if args.manifest_out.resolve() == output.resolve():
                raise CompileError("--manifest-out and --output must be different files")
            if args.manifest_out.exists() and not args.force:
                raise CompileError(
                    f"manifest output already exists: {args.manifest_out} (use --force)"
                )

        image = build_executable(manifest, args.base_address)
        write_executable(output, image, force=args.force)
        if args.manifest_out is not None:
            write_manifest(args.manifest_out, manifest, force=args.force)
    except CompileError as exc:
        fail(str(exc))
    except OSError as exc:
        fail(str(exc))

    output = output.resolve()
    if not args.quiet:
        print(
            f"wrote {output} ({len(image)} bytes, "
            f"{len(manifest.shellcode)}-byte {manifest.architecture} payload, "
            f"{manifest.target.binary_format})"
        )
        if manifest.description:
            print(manifest.description)
        if manifest.target.manifest_name == "aarch64-macos":
            print("note: Apple Silicon may require: codesign --sign - <output>")

    if args.run:
        if not host_can_run(manifest.target):
            fail(
                f"--run requires a {manifest.target.os_name}/"
                f"{manifest.target.architecture} host"
            )
        completed = subprocess.run([str(output), *args.arg], check=False)
        return completed.returncode
    return 0
