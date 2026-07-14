from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from .errors import CompileError
from .manifest import Manifest
from .targets import Target


def load_manifest(
    path: Path, max_payload: int, expected_target: Target | None = None
) -> Manifest:
    try:
        with path.open("r", encoding="utf-8") as stream:
            value = json.load(stream)
    except OSError as exc:
        raise CompileError(f"cannot read manifest {path}: {exc.strerror}") from exc
    except json.JSONDecodeError as exc:
        raise CompileError(f"invalid manifest JSON in {path}: {exc}") from exc
    return Manifest.from_mapping(
        value, max_payload=max_payload, expected_target=expected_target
    )


def write_executable(path: Path, content: bytes, *, force: bool) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    if not force:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o755)
        except FileExistsError as exc:
            raise CompileError(f"output already exists: {path} (use --force)") from exc
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        return

    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
            temporary_name = stream.name
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary_name, 0o755)
        os.replace(temporary_name, path)
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)


def write_manifest(path: Path, manifest: Manifest, *, force: bool) -> None:
    if path.exists() and not force:
        raise CompileError(f"manifest output already exists: {path} (use --force)")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest.as_json(), indent=2) + "\n", encoding="utf-8")
