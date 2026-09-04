from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from scripts import build_w09_native as native_build


def _fake_repository(root: Path) -> Path:
    source_root = root / "snapquiz" / "transport" / "native"
    source_root.mkdir(parents=True)
    for target in native_build.NATIVE_TARGETS:
        (source_root / target.source_name).write_text(
            f"int {target.name}_fixture(void) {{ return 0; }}\n",
            encoding="utf-8",
        )
    for input_name in native_build.NATIVE_SHARED_INPUTS:
        (source_root / input_name).write_text(
            "#ifndef SNAPQUIZ_NATIVE_FIXTURE_H\n"
            "#define SNAPQUIZ_NATIVE_FIXTURE_H\n"
            "#endif\n",
            encoding="utf-8",
        )
    return root


class W09NativeBuildTest(unittest.TestCase):
    def test_target_inventory_is_fixed_unique_and_non_production(self):
        self.assertEqual(
            tuple(target.name for target in native_build.NATIVE_TARGETS),
            (
                "spawn_outcome",
                "resolver_owner",
                "numeric_owner",
                "tls_owner",
            ),
        )
        self.assertEqual(
            len({target.source_name for target in native_build.NATIVE_TARGETS}),
            len(native_build.NATIVE_TARGETS),
        )
        self.assertEqual(
            len({target.output_name for target in native_build.NATIVE_TARGETS}),
            len(native_build.NATIVE_TARGETS),
        )
        self.assertTrue(
            all(target.output_name.endswith(".dylib") for target in native_build.NATIVE_TARGETS)
        )
        self.assertEqual(
            native_build.NATIVE_SHARED_INPUTS,
            ("darwin_owner_transfer.h",),
        )

    def test_commands_are_shell_free_strict_and_never_invoke_codesign(self):
        clang = Path("/toolchain/clang")
        sdk = Path("/sdk")
        source = Path("/src/owner.c")
        output = Path("/different/build/root/.owner.dylib.building")
        syntax = native_build._syntax_command(
            clang=clang,
            sdk=sdk,
            source=source,
        )
        build = native_build._build_command(
            clang=clang,
            sdk=sdk,
            source=source,
            output=output,
        )
        for command in (syntax, build):
            self.assertIs(type(command), tuple)
            self.assertIn("-Wall", command)
            self.assertIn("-Wextra", command)
            self.assertIn("-Werror", command)
            self.assertNotIn("codesign", command)
            self.assertNotIn("sh", command[:1])
        self.assertIn("-fsyntax-only", syntax)
        self.assertIn("-dynamiclib", build)
        self.assertIn(
            "-Wl,-install_name,@rpath/owner.dylib",
            build,
        )

    def test_simulated_build_creates_content_addressed_nonproduction_manifest(self):
        with tempfile.TemporaryDirectory() as selected:
            temporary = Path(selected)
            repository = _fake_repository(temporary / "repo")
            destination = temporary / "out" / "native"

            def fake_run(arguments):
                if "-o" not in arguments:
                    return
                output = Path(arguments[arguments.index("-o") + 1])
                source = Path(arguments[-3])
                output.write_bytes(b"dylib-fixture:" + source.read_bytes())

            with mock.patch.object(
                native_build,
                "_resolve_toolchain",
                return_value=(Path("/toolchain/clang"), Path("/sdk")),
            ), mock.patch.object(
                native_build,
                "_toolchain_manifest",
                return_value={"synthetic": "fixed-toolchain"},
            ), mock.patch.object(native_build, "_run", side_effect=fake_run):
                manifest_path = native_build.build_sources(
                    repository,
                    destination,
                )

            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(
                payload["schema_version"],
                native_build.NATIVE_BUILD_MANIFEST_SCHEMA_VERSION,
            )
            self.assertEqual(
                payload["signature_class"],
                "development_linker_adhoc_or_unsigned",
            )
            self.assertFalse(payload["production_signed"])
            self.assertFalse(payload["production_authority"])
            self.assertEqual(
                payload["toolchain"],
                {"synthetic": "fixed-toolchain"},
            )
            self.assertEqual(payload["target_count"], 4)
            self.assertEqual(len(payload["targets"]), 4)
            self.assertEqual(payload["shared_input_count"], 1)
            self.assertEqual(len(payload["shared_inputs"]), 1)
            shared = payload["shared_inputs"][0]
            self.assertEqual(shared["name"], "darwin_owner_transfer.h")
            self.assertEqual(shared["snapshot"], "darwin_owner_transfer.h")
            self.assertRegex(shared["sha256"], r"\A[0-9a-f]{64}\Z")
            self.assertEqual(
                native_build._sha256(manifest_path.parent / shared["snapshot"]),
                shared["sha256"],
            )
            self.assertEqual(
                (manifest_path.parent / shared["snapshot"]).stat().st_mode & 0o777,
                0o400,
            )
            self.assertEqual(
                (manifest_path.parent / shared["snapshot"]).stat().st_nlink,
                1,
            )
            self.assertEqual(manifest_path.stat().st_mode & 0o777, 0o400)
            self.assertEqual(manifest_path.stat().st_nlink, 1)
            for item in payload["targets"]:
                self.assertRegex(item["source_sha256"], r"\A[0-9a-f]{64}\Z")
                self.assertRegex(item["output_sha256"], r"\A[0-9a-f]{64}\Z")
                snapshot = manifest_path.parent / item["source_snapshot"]
                self.assertTrue(snapshot.is_file())
                self.assertEqual(snapshot.stat().st_mode & 0o777, 0o400)
                self.assertEqual(snapshot.stat().st_nlink, 1)
                self.assertEqual(
                    native_build._sha256(snapshot),
                    item["source_sha256"],
                )

    def test_existing_destination_is_never_replaced(self):
        with tempfile.TemporaryDirectory() as selected:
            temporary = Path(selected)
            repository = _fake_repository(temporary / "repo")
            destination = temporary / "existing"
            destination.mkdir()
            sentinel = destination / "sentinel"
            sentinel.write_text("keep", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                native_build.build_sources(repository, destination)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")

    def test_symlink_destination_is_never_followed(self):
        with tempfile.TemporaryDirectory() as selected:
            temporary = Path(selected)
            repository = _fake_repository(temporary / "repo")
            victim = temporary / "victim"
            victim.mkdir()
            destination = temporary / "native"
            destination.symlink_to(victim, target_is_directory=True)

            with self.assertRaisesRegex(RuntimeError, "already exists"):
                native_build.build_sources(repository, destination)

            self.assertEqual(tuple(victim.iterdir()), ())

    def test_destination_fd_is_closed_when_path_identity_observation_fails(self):
        with tempfile.TemporaryDirectory() as selected:
            temporary = Path(selected)
            destination = temporary / "native"
            real_open = native_build.os.open
            real_lstat = native_build.os.lstat
            captured: list[int] = []

            def tracking_open(path, flags, mode=0o777, *, dir_fd=None):
                file_descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
                if path == destination.name and dir_fd is not None:
                    captured.append(file_descriptor)
                return file_descriptor

            def failing_lstat(path, *args, **kwargs):
                if captured:
                    raise OSError("simulated destination path race")
                return real_lstat(path, *args, **kwargs)

            with mock.patch.object(
                native_build.os,
                "open",
                side_effect=tracking_open,
            ), mock.patch.object(
                native_build.os,
                "lstat",
                side_effect=failing_lstat,
            ):
                with self.assertRaisesRegex(OSError, "path race"):
                    native_build._open_new_destination(destination)

            self.assertEqual(len(captured), 1)
            with self.assertRaises(OSError):
                os.fstat(captured[0])

    def test_source_fd_is_closed_when_snapshot_creation_fails(self):
        with tempfile.TemporaryDirectory() as selected:
            temporary = Path(selected)
            source = temporary / "source.c"
            source.write_text("int fixture(void) { return 0; }\n", encoding="utf-8")
            destination, destination_fd = native_build._open_new_destination(
                temporary / "native"
            )
            (destination / ".source.c").write_text("collision", encoding="utf-8")
            real_open = native_build.os.open
            captured: list[int] = []

            def tracking_open(path, flags, mode=0o777, *, dir_fd=None):
                file_descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
                if Path(path) == source:
                    captured.append(file_descriptor)
                return file_descriptor

            try:
                with mock.patch.object(
                    native_build.os,
                    "open",
                    side_effect=tracking_open,
                ):
                    with self.assertRaises(FileExistsError):
                        native_build._snapshot_regular_input(
                            source=source,
                            destination=destination,
                            destination_fd=destination_fd,
                            snapshot_name=".source.c",
                            label="source.c",
                        )
                self.assertEqual(len(captured), 1)
                with self.assertRaises(OSError):
                    os.fstat(captured[0])
            finally:
                os.close(destination_fd)

    def test_shared_header_symlink_is_rejected_before_build(self):
        with tempfile.TemporaryDirectory() as selected:
            temporary = Path(selected)
            repository = _fake_repository(temporary / "repo")
            source_root = repository / "snapquiz" / "transport" / "native"
            header = source_root / native_build.NATIVE_SHARED_INPUTS[0]
            victim = temporary / "outside.h"
            victim.write_text("/* outside */\n", encoding="utf-8")
            header.unlink()
            header.symlink_to(victim)

            with self.assertRaisesRegex(RuntimeError, "regular native input"):
                native_build._validated_shared_inputs(repository)

    def test_tools_use_fixed_xcrun_and_minimal_environment(self):
        completed = mock.Mock(stdout="/fixed/tool\n")
        with mock.patch.object(
            native_build.subprocess,
            "run",
            return_value=completed,
        ) as run:
            self.assertEqual(
                native_build._tool_output(
                    (str(native_build._XCRUN), "--find", "clang")
                ),
                "/fixed/tool",
            )
        arguments, keywords = run.call_args
        self.assertEqual(arguments[0][0], "/usr/bin/xcrun")
        self.assertEqual(
            keywords["env"],
            native_build._CLEAN_BUILD_ENVIRONMENT,
        )
        self.assertNotIn("CPATH", keywords["env"])
        self.assertNotIn("DEVELOPER_DIR", keywords["env"])
        self.assertTrue(keywords["close_fds"])

    def test_linker_inode_replacement_is_reopened_sealed_and_hashed(self):
        with tempfile.TemporaryDirectory() as selected:
            temporary = Path(selected)
            repository = _fake_repository(temporary / "repo")
            destination = temporary / "out"

            def replace_output(arguments):
                if "-o" not in arguments:
                    return
                output = Path(arguments[arguments.index("-o") + 1])
                os.unlink(output)
                output.write_bytes(b"replacement")

            with mock.patch.object(
                native_build,
                "_resolve_toolchain",
                return_value=(Path("/toolchain/clang"), Path("/sdk")),
            ), mock.patch.object(
                native_build,
                "_toolchain_manifest",
                return_value={"synthetic": "fixed-toolchain"},
            ), mock.patch.object(
                native_build,
                "_run",
                side_effect=replace_output,
            ):
                manifest_path = native_build.build_sources(repository, destination)
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertTrue(
                all(
                    item["linker_replaced_staging_inode"]
                    for item in payload["targets"]
                )
            )
            for item in payload["targets"]:
                output = destination / item["output"]
                self.assertEqual(output.stat().st_mode & 0o777, 0o500)
                self.assertEqual(
                    native_build._sha256(output),
                    item["output_sha256"],
                )

    def test_compiler_symlink_output_is_rejected_without_touching_victim(self):
        with tempfile.TemporaryDirectory() as selected:
            temporary = Path(selected)
            repository = _fake_repository(temporary / "repo")
            destination = temporary / "out"
            victim = temporary / "victim"
            victim.write_bytes(b"keep")

            def replace_output_with_symlink(arguments):
                if "-o" not in arguments:
                    return
                output = Path(arguments[arguments.index("-o") + 1])
                os.unlink(output)
                output.symlink_to(victim)

            with mock.patch.object(
                native_build,
                "_resolve_toolchain",
                return_value=(Path("/toolchain/clang"), Path("/sdk")),
            ), mock.patch.object(
                native_build,
                "_toolchain_manifest",
                return_value={"synthetic": "fixed-toolchain"},
            ), mock.patch.object(
                native_build,
                "_run",
                side_effect=replace_output_with_symlink,
            ):
                with self.assertRaisesRegex(RuntimeError, "safe regular file"):
                    native_build.build_sources(repository, destination)
            self.assertEqual(victim.read_bytes(), b"keep")
            self.assertFalse((destination / "manifest.json").exists())

    def test_compiler_hardlink_output_is_rejected_without_touching_victim(self):
        with tempfile.TemporaryDirectory() as selected:
            temporary = Path(selected)
            repository = _fake_repository(temporary / "repo")
            destination = temporary / "out"
            victim = temporary / "victim"
            victim.write_bytes(b"keep")

            def replace_output_with_hardlink(arguments):
                if "-o" not in arguments:
                    return
                output = Path(arguments[arguments.index("-o") + 1])
                os.unlink(output)
                os.link(victim, output)

            with mock.patch.object(
                native_build,
                "_resolve_toolchain",
                return_value=(Path("/toolchain/clang"), Path("/sdk")),
            ), mock.patch.object(
                native_build,
                "_toolchain_manifest",
                return_value={"synthetic": "fixed-toolchain"},
            ), mock.patch.object(
                native_build,
                "_run",
                side_effect=replace_output_with_hardlink,
            ):
                with self.assertRaisesRegex(RuntimeError, "unlinked file"):
                    native_build.build_sources(repository, destination)
            self.assertEqual(victim.read_bytes(), b"keep")
            self.assertFalse((destination / "manifest.json").exists())

    def test_manifest_symlink_is_never_followed_or_overwritten(self):
        with tempfile.TemporaryDirectory() as selected:
            temporary = Path(selected)
            repository = _fake_repository(temporary / "repo")
            destination = temporary / "out"
            victim = temporary / "victim"
            victim.write_text("keep", encoding="utf-8")
            build_count = 0

            def fake_run(arguments):
                nonlocal build_count
                if "-o" not in arguments:
                    return
                output = Path(arguments[arguments.index("-o") + 1])
                source = Path(arguments[-3])
                output.write_bytes(b"dylib-fixture:" + source.read_bytes())
                build_count += 1
                if build_count == len(native_build.NATIVE_TARGETS):
                    (destination / "manifest.json").symlink_to(victim)

            with mock.patch.object(
                native_build,
                "_resolve_toolchain",
                return_value=(Path("/toolchain/clang"), Path("/sdk")),
            ), mock.patch.object(
                native_build,
                "_toolchain_manifest",
                return_value={"synthetic": "fixed-toolchain"},
            ), mock.patch.object(native_build, "_run", side_effect=fake_run):
                with self.assertRaises(FileExistsError):
                    native_build.build_sources(repository, destination)
            self.assertEqual(victim.read_text(encoding="utf-8"), "keep")

    def test_interrupted_manifest_write_never_publishes_final_name(self):
        with tempfile.TemporaryDirectory() as selected:
            destination, destination_fd = native_build._open_new_destination(
                Path(selected) / "native"
            )

            def partial_write(file_descriptor, value):
                os.write(file_descriptor, value[:8])
                raise OSError("simulated interrupted manifest write")

            try:
                with mock.patch.object(
                    native_build,
                    "_write_all",
                    side_effect=partial_write,
                ):
                    with self.assertRaisesRegex(OSError, "interrupted manifest"):
                        native_build._write_manifest_exclusive(
                            destination=destination,
                            destination_fd=destination_fd,
                            payload={"complete": True},
                        )
                self.assertFalse((destination / "manifest.json").exists())
                self.assertTrue((destination / ".manifest.json.building").is_file())
            finally:
                os.close(destination_fd)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin-only native build")
    def test_real_builds_are_byte_for_byte_reproducible(self):
        repository = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as selected:
            temporary = Path(selected)
            first = temporary / "first"
            second = temporary / "second"
            first_manifest = native_build.build_sources(repository, first)
            second_manifest = native_build.build_sources(repository, second)

            first_files = {
                item.name: item.read_bytes() for item in first.iterdir()
            }
            second_files = {
                item.name: item.read_bytes() for item in second.iterdir()
            }
            self.assertEqual(first_files, second_files)
            self.assertFalse(
                any(name.endswith(".building") for name in first_files)
            )
            payload = json.loads(first_manifest.read_text(encoding="utf-8"))
            self.assertEqual(first_manifest.stat().st_mode & 0o777, 0o400)
            self.assertEqual(second_manifest.stat().st_mode & 0o777, 0o400)
            self.assertEqual(
                payload["signature_class"],
                "development_linker_adhoc_or_unsigned",
            )
            self.assertFalse(payload["production_signed"])
            self.assertFalse(payload["production_authority"])
            self.assertTrue(
                all(
                    item["linker_replaced_staging_inode"]
                    for item in payload["targets"]
                )
            )

    @unittest.skipUnless(sys.platform == "darwin", "Darwin-only native ABI")
    def test_repository_sources_pass_unified_strict_syntax_target(self):
        native_build.check_sources(Path(__file__).resolve().parents[1])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
