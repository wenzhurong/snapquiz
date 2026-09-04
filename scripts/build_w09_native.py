#!/usr/bin/env python3
"""Reproducibly compile the W09 native owner foundations on macOS.

This is a development build target, not a production signing or activation
tool.  It never invokes ``codesign``, reads credentials, starts a helper, or
enables any SnapQuiz production flag.  Build output is written only to a new
explicit directory; an existing directory is never replaced.  Apple clang may
add a linker ad-hoc signature automatically; that is explicitly not a Team
identity or a production signature.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import NamedTuple, Sequence


NATIVE_BUILD_MANIFEST_SCHEMA_VERSION = "snapquiz.w09-native-build.v2"
_XCRUN = Path("/usr/bin/xcrun")
_CLEAN_BUILD_ENVIRONMENT = {
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    "SOURCE_DATE_EPOCH": "0",
    "ZERO_AR_DATE": "1",
}


class NativeTarget(NamedTuple):
    name: str
    source_name: str
    output_name: str


NATIVE_TARGETS = (
    NativeTarget(
        "spawn_outcome",
        "darwin_spawn_outcome.c",
        "libsnapquiz_spawn_outcome.dylib",
    ),
    NativeTarget(
        "resolver_owner",
        "darwin_resolver_owner.c",
        "libsnapquiz_resolver_owner.dylib",
    ),
    NativeTarget(
        "numeric_owner",
        "darwin_numeric_owner.c",
        "libsnapquiz_numeric_owner.dylib",
    ),
    NativeTarget(
        "tls_owner",
        "darwin_tls_owner.c",
        "libsnapquiz_tls_owner.dylib",
    ),
)

# Quoted headers shared by more than one owner ABI are immutable build inputs,
# not ambient include-path state.  They are copied into the new build directory
# before clang runs and are content-addressed in the manifest.
NATIVE_SHARED_INPUTS = ("darwin_owner_transfer.h",)


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _native_source_root(repository_root: Path) -> Path:
    return repository_root / "snapquiz" / "transport" / "native"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(128 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_fd(file_descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(file_descriptor, 0, os.SEEK_SET)
    while True:
        chunk = os.read(file_descriptor, 128 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    os.lseek(file_descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def _tool_output(arguments: Sequence[str]) -> str:
    completed = subprocess.run(
        tuple(arguments),
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        env=dict(_CLEAN_BUILD_ENVIRONMENT),
        close_fds=True,
    )
    value = completed.stdout.strip()
    if not value or "\x00" in value or "\n" in value or "\r" in value:
        raise RuntimeError("native tool returned an invalid path")
    return value


def _resolve_toolchain() -> tuple[Path, Path]:
    if sys.platform != "darwin":
        raise RuntimeError("W09 native owners can only be built on macOS")
    if _XCRUN.is_symlink() or not _XCRUN.is_file():
        raise RuntimeError("fixed xcrun executable is unavailable")
    clang = Path(_tool_output((str(_XCRUN), "--find", "clang")))
    sdk = Path(
        _tool_output(
            (str(_XCRUN), "--sdk", "macosx", "--show-sdk-path")
        )
    )
    if not clang.is_absolute() or not clang.is_file() or clang.is_symlink():
        raise RuntimeError("xcrun returned an invalid clang executable")
    if not sdk.is_absolute() or not sdk.is_dir():
        raise RuntimeError("xcrun returned an invalid macOS SDK")
    return clang, sdk


def _validated_sources(repository_root: Path) -> tuple[tuple[NativeTarget, Path], ...]:
    source_root = _native_source_root(repository_root).resolve(strict=True)
    selected: list[tuple[NativeTarget, Path]] = []
    for target in NATIVE_TARGETS:
        source = source_root / target.source_name
        if source.is_symlink() or not source.is_file():
            raise RuntimeError(f"missing regular native source: {target.source_name}")
        resolved = source.resolve(strict=True)
        if resolved.parent != source_root:
            raise RuntimeError(f"native source escaped source root: {target.source_name}")
        selected.append((target, resolved))
    return tuple(selected)


def _validated_shared_inputs(repository_root: Path) -> tuple[Path, ...]:
    source_root = _native_source_root(repository_root).resolve(strict=True)
    selected: list[Path] = []
    for input_name in NATIVE_SHARED_INPUTS:
        source = source_root / input_name
        if source.is_symlink() or not source.is_file():
            raise RuntimeError(f"missing regular native input: {input_name}")
        resolved = source.resolve(strict=True)
        if resolved.parent != source_root:
            raise RuntimeError(f"native input escaped source root: {input_name}")
        selected.append(resolved)
    return tuple(selected)


def _syntax_command(*, clang: Path, sdk: Path, source: Path) -> tuple[str, ...]:
    return (
        str(clang),
        "-isysroot",
        str(sdk),
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-fsyntax-only",
        str(source),
    )


def _build_command(
    *,
    clang: Path,
    sdk: Path,
    source: Path,
    output: Path,
) -> tuple[str, ...]:
    return (
        str(clang),
        "-isysroot",
        str(sdk),
        "-std=c11",
        "-O2",
        "-fstack-protector-strong",
        "-fno-common",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-dynamiclib",
        "-Wl,-dead_strip",
        f"-Wl,-install_name,@rpath/{output.name.removeprefix('.').removesuffix('.building')}",
        str(source),
        "-o",
        str(output),
    )


def _run(arguments: Sequence[str]) -> None:
    subprocess.run(
        tuple(arguments),
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env=dict(_CLEAN_BUILD_ENVIRONMENT),
        close_fds=True,
    )


class _FileIdentity(NamedTuple):
    device: int
    inode: int
    mode: int
    size: int
    modified_ns: int
    changed_ns: int


def _file_identity(selected: os.stat_result) -> _FileIdentity:
    return _FileIdentity(
        selected.st_dev,
        selected.st_ino,
        selected.st_mode,
        selected.st_size,
        selected.st_mtime_ns,
        selected.st_ctime_ns,
    )


def _require_regular_identity(selected: os.stat_result, label: str) -> None:
    if not stat.S_ISREG(selected.st_mode) or selected.st_nlink != 1:
        raise RuntimeError(f"{label} must be one regular unlinked file")


def _write_all(file_descriptor: int, value: bytes) -> None:
    offset = 0
    while offset < len(value):
        written = os.write(file_descriptor, value[offset:])
        if written <= 0:
            raise RuntimeError("native build write did not progress")
        offset += written


def _open_new_destination(output_dir: Path) -> tuple[Path, int]:
    requested = output_dir.expanduser()
    if requested.name in ("", ".", ".."):
        raise RuntimeError("output directory is invalid")
    requested.parent.mkdir(parents=True, exist_ok=True)
    parent = requested.parent.resolve(strict=True)
    destination = parent / requested.name
    parent_flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        parent_flags |= os.O_NOFOLLOW
    parent_fd = os.open(parent, parent_flags)
    try:
        try:
            os.mkdir(destination.name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            raise RuntimeError("output directory already exists") from None
        directory_flags = os.O_RDONLY | os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            directory_flags |= os.O_NOFOLLOW
        destination_fd = os.open(
            destination.name,
            directory_flags,
            dir_fd=parent_fd,
        )
    finally:
        os.close(parent_fd)
    try:
        selected = os.fstat(destination_fd)
        observed = os.lstat(destination)
        if (
            not stat.S_ISDIR(selected.st_mode)
            or _file_identity(selected) != _file_identity(observed)
            or stat.S_IMODE(selected.st_mode) != 0o700
        ):
            raise RuntimeError("new output directory identity is invalid")
    except BaseException:
        os.close(destination_fd)
        raise
    return destination, destination_fd


def _snapshot_regular_input(
    *,
    source: Path,
    destination: Path,
    destination_fd: int,
    snapshot_name: str,
    label: str,
) -> tuple[Path, str]:
    source_flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        source_flags |= os.O_NOFOLLOW
    source_fd = os.open(source, source_flags)
    snapshot_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        snapshot_flags |= os.O_NOFOLLOW
    try:
        snapshot_fd = os.open(
            snapshot_name,
            snapshot_flags,
            0o400,
            dir_fd=destination_fd,
        )
        digest = hashlib.sha256()
        try:
            before = os.fstat(source_fd)
            _require_regular_identity(before, label)
            while True:
                chunk = os.read(source_fd, 128 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                _write_all(snapshot_fd, chunk)
            os.fchmod(snapshot_fd, 0o400)
            os.fsync(snapshot_fd)
            snapshot_identity = os.fstat(snapshot_fd)
            _require_regular_identity(snapshot_identity, snapshot_name)
            after = os.fstat(source_fd)
            path_after = os.lstat(source)
            if (
                _file_identity(before) != _file_identity(after)
                or _file_identity(after) != _file_identity(path_after)
            ):
                raise RuntimeError(
                    f"native source changed while snapshotting: {label}"
                )
        finally:
            os.close(snapshot_fd)
    finally:
        os.close(source_fd)
    snapshot = destination / snapshot_name
    snapshot_selected = os.lstat(snapshot)
    _require_regular_identity(snapshot_selected, snapshot_name)
    if (
        _file_identity(snapshot_selected) != _file_identity(snapshot_identity)
        or snapshot_selected.st_size != after.st_size
        or stat.S_IMODE(snapshot_selected.st_mode) != 0o400
    ):
        raise RuntimeError(f"native source snapshot is incomplete: {label}")
    return snapshot, digest.hexdigest()


def _snapshot_source(
    *,
    source: Path,
    destination: Path,
    destination_fd: int,
    target: NativeTarget,
) -> tuple[Path, str]:
    return _snapshot_regular_input(
        source=source,
        destination=destination,
        destination_fd=destination_fd,
        snapshot_name=f".{target.name}.source.c",
        label=target.source_name,
    )


def _prepare_output(
    *,
    destination: Path,
    destination_fd: int,
    target: NativeTarget,
) -> tuple[Path, str, _FileIdentity]:
    staging_name = f".{target.output_name}.building"
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    staging_fd = os.open(staging_name, flags, 0o600, dir_fd=destination_fd)
    try:
        selected = os.fstat(staging_fd)
        _require_regular_identity(selected, staging_name)
        identity = _file_identity(selected)
    finally:
        os.close(staging_fd)
    return destination / staging_name, staging_name, identity


def _publish_verified_output(
    *,
    destination: Path,
    destination_fd: int,
    staging_name: str,
    initial_identity: _FileIdentity,
    target: NativeTarget,
) -> tuple[int, str, _FileIdentity, bool]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        staging_fd = os.open(staging_name, flags, dir_fd=destination_fd)
    except OSError:
        raise RuntimeError(
            f"compiler output is not a safe regular file: {target.output_name}"
        ) from None
    try:
        selected = os.fstat(staging_fd)
        observed = os.lstat(destination / staging_name)
        if _file_identity(selected) != _file_identity(observed):
            raise RuntimeError(f"compiler output path changed: {target.output_name}")
        _require_regular_identity(selected, target.output_name)
        linker_replaced_inode = (
            selected.st_dev != initial_identity.device
            or selected.st_ino != initial_identity.inode
        )
        # Apple's linker atomically replaces an existing ``-o`` path.  That one
        # replacement is expected from the fixed, hashed toolchain; trust does
        # not extend to the resulting pathname.  Re-open/identity validation
        # above, then seal the captured inode before hashing and publication.
        os.fchmod(staging_fd, 0o500)
        os.fsync(staging_fd)
        selected = os.fstat(staging_fd)
        observed = os.lstat(destination / staging_name)
        if _file_identity(selected) != _file_identity(observed):
            raise RuntimeError(
                f"compiler output changed while sealing: {target.output_name}"
            )
        _require_regular_identity(selected, target.output_name)
        output_hash = _sha256_fd(staging_fd)
        after_hash = os.fstat(staging_fd)
        if _file_identity(selected) != _file_identity(after_hash):
            raise RuntimeError(
                f"compiler output changed while hashing: {target.output_name}"
            )
        try:
            os.link(
                staging_name,
                target.output_name,
                src_dir_fd=destination_fd,
                dst_dir_fd=destination_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            raise RuntimeError(f"refusing to replace {target.output_name}") from None
        os.unlink(staging_name, dir_fd=destination_fd)
        final_observed = os.lstat(destination / target.output_name)
        _require_regular_identity(final_observed, target.output_name)
        if (
            final_observed.st_dev != selected.st_dev
            or final_observed.st_ino != selected.st_ino
            or stat.S_IMODE(final_observed.st_mode) != 0o500
        ):
            raise RuntimeError(
                f"published output identity changed: {target.output_name}"
            )
        return (
            staging_fd,
            output_hash,
            _file_identity(final_observed),
            linker_replaced_inode,
        )
    except BaseException:
        os.close(staging_fd)
        raise


def _write_manifest_exclusive(
    *,
    destination: Path,
    destination_fd: int,
    payload: dict[str, object],
) -> Path:
    encoded = (
        json.dumps(payload, ensure_ascii=True, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")
    staging_name = ".manifest.json.building"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    manifest_fd = os.open(
        staging_name,
        flags,
        0o600,
        dir_fd=destination_fd,
    )
    try:
        initial = os.fstat(manifest_fd)
        _require_regular_identity(initial, staging_name)
        _write_all(manifest_fd, encoded)
        os.fchmod(manifest_fd, 0o400)
        os.fsync(manifest_fd)
        sealed = os.fstat(manifest_fd)
        observed = os.lstat(destination / staging_name)
        _require_regular_identity(sealed, staging_name)
        if (
            _file_identity(sealed) != _file_identity(observed)
            or stat.S_IMODE(sealed.st_mode) != 0o400
        ):
            raise RuntimeError("native build manifest changed while sealing")
        os.link(
            staging_name,
            "manifest.json",
            src_dir_fd=destination_fd,
            dst_dir_fd=destination_fd,
            follow_symlinks=False,
        )
        os.unlink(staging_name, dir_fd=destination_fd)
        final_observed = os.lstat(destination / "manifest.json")
        _require_regular_identity(final_observed, "manifest.json")
        if (
            final_observed.st_dev != sealed.st_dev
            or final_observed.st_ino != sealed.st_ino
            or stat.S_IMODE(final_observed.st_mode) != 0o400
        ):
            raise RuntimeError("published native build manifest changed")
    finally:
        os.close(manifest_fd)
    return destination / "manifest.json"


def _toolchain_manifest(clang: Path, sdk: Path) -> dict[str, object]:
    sdk_settings = sdk / "SDKSettings.plist"
    if sdk_settings.is_symlink() or not sdk_settings.is_file():
        raise RuntimeError("macOS SDK identity marker is unavailable")
    return {
        "xcrun_path": str(_XCRUN),
        "xcrun_sha256": _sha256(_XCRUN),
        "clang_path": str(clang),
        "clang_sha256": _sha256(clang),
        "sdk_path": str(sdk),
        "sdk_settings_sha256": _sha256(sdk_settings),
        "environment_keys": tuple(sorted(_CLEAN_BUILD_ENVIRONMENT)),
    }


def check_sources(repository_root: Path) -> None:
    root = repository_root.resolve(strict=True)
    clang, sdk = _resolve_toolchain()
    sources = _validated_sources(root)
    inputs = tuple(source for _, source in sources) + _validated_shared_inputs(root)
    before = tuple((source, _sha256(source)) for source in inputs)
    for _, source in sources:
        _run(_syntax_command(clang=clang, sdk=sdk, source=source))
    for source, expected_hash in before:
        if _sha256(source) != expected_hash:
            raise RuntimeError("native source changed during strict syntax check")


def build_sources(repository_root: Path, output_dir: Path) -> Path:
    root = repository_root.resolve(strict=True)
    destination, destination_fd = _open_new_destination(output_dir)
    retained_outputs: list[tuple[int, Path, _FileIdentity, str]] = []
    try:
        clang, sdk = _resolve_toolchain()
        toolchain = _toolchain_manifest(clang, sdk)
        sources = _validated_sources(root)
        manifest_shared_inputs: list[dict[str, object]] = []
        for shared_input in _validated_shared_inputs(root):
            snapshot, input_hash = _snapshot_regular_input(
                source=shared_input,
                destination=destination,
                destination_fd=destination_fd,
                snapshot_name=shared_input.name,
                label=shared_input.name,
            )
            manifest_shared_inputs.append(
                {
                    "name": shared_input.name,
                    "snapshot": snapshot.name,
                    "sha256": input_hash,
                }
            )
        manifest_targets: list[dict[str, object]] = []
        for target, source in sources:
            snapshot, source_hash = _snapshot_source(
                source=source,
                destination=destination,
                destination_fd=destination_fd,
                target=target,
            )
            staging, staging_name, staging_identity = _prepare_output(
                destination=destination,
                destination_fd=destination_fd,
                target=target,
            )
            _run(
                _build_command(
                    clang=clang,
                    sdk=sdk,
                    source=snapshot,
                    output=staging,
                )
            )
            (
                output_fd,
                output_hash,
                output_identity,
                linker_replaced_inode,
            ) = _publish_verified_output(
                destination=destination,
                destination_fd=destination_fd,
                staging_name=staging_name,
                initial_identity=staging_identity,
                target=target,
            )
            output = destination / target.output_name
            retained_outputs.append(
                (output_fd, output, output_identity, output_hash)
            )
            manifest_targets.append(
                {
                    "name": target.name,
                    "source": target.source_name,
                    "source_snapshot": snapshot.name,
                    "source_sha256": source_hash,
                    "output": target.output_name,
                    "output_sha256": output_hash,
                    "linker_replaced_staging_inode": linker_replaced_inode,
                }
            )

        # Keep each verified output inode open until the manifest has been
        # assembled, and reject any path or content replacement before publish.
        for output_fd, output, identity, expected_hash in retained_outputs:
            selected = os.fstat(output_fd)
            observed = os.lstat(output)
            if (
                _file_identity(selected) != identity
                or _file_identity(observed) != identity
                or _sha256_fd(output_fd) != expected_hash
            ):
                raise RuntimeError("native output changed before manifest publish")

        if _toolchain_manifest(clang, sdk) != toolchain:
            raise RuntimeError("native toolchain changed during build")
        manifest = {
            "schema_version": NATIVE_BUILD_MANIFEST_SCHEMA_VERSION,
            "signature_class": "development_linker_adhoc_or_unsigned",
            "production_signed": False,
            "production_authority": False,
            "toolchain": toolchain,
            "shared_input_count": len(manifest_shared_inputs),
            "shared_inputs": manifest_shared_inputs,
            "target_count": len(manifest_targets),
            "targets": manifest_targets,
        }
        manifest_path = _write_manifest_exclusive(
            destination=destination,
            destination_fd=destination_fd,
            payload=manifest,
        )
        os.fsync(destination_fd)
        return manifest_path
    finally:
        for output_fd, _, _, _ in retained_outputs:
            os.close(output_fd)
        os.close(destination_fd)


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compile non-production W09 native owner foundations",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="run strict C syntax checks without writing build output",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="new directory for non-production development dylibs",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    root = _repository_root()
    if args.check_only:
        if args.output_dir is not None:
            raise SystemExit("--check-only and --output-dir are mutually exclusive")
        check_sources(root)
        return 0
    if args.output_dir is None:
        raise SystemExit("--output-dir is required unless --check-only is used")
    manifest = build_sources(root, args.output_dir)
    print(manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
