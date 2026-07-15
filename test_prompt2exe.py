import io
import json
import os
import platform
import struct
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

import prompt2exe as compiler
from prompt2exe import api as compiler_api
from prompt2exe import cli as compiler_cli
from prompt2exe.flow import TerminalFlowWriter, display_width
from prompt2exe.review import build_review_prompt
from prompt2exe.throbber import Throbber


HELLO_HEX = (
    "b801000000bf01000000488d3510000000ba0b0000000f05"
    "b83c00000031ff0f0568656c6c6f20776f726c64"
)


def hello_mapping(architecture="x86_64-linux", shellcode_hex=HELLO_HEX):
    return {
        "architecture": architecture,
        "shellcode_hex": shellcode_hex,
        "entry_offset": 0,
        "description": "writes hello world",
    }


def reloc_mapping(architecture, chunks, fixups=(), entry="entry"):
    return {
        "architecture": architecture,
        "chunks": chunks,
        "entry": entry,
        "fixups": list(fixups),
        "description": "relocation test",
    }


def reloc_hello_mapping():
    return reloc_mapping(
        "x86_64-linux",
        [
            {
                "label": "entry",
                "kind": "code",
                "hex": "b801000000bf01000000488d3500000000",
            },
            {
                "label": "write_and_exit",
                "kind": "code",
                "hex": "ba0b0000000f05b83c00000031ff0f05",
            },
            {"label": "message", "kind": "data", "hex": "68656c6c6f20776f726c64"},
        ],
        [
            {
                "source": "entry",
                "kind": "x86_rip_rel32",
                "target": "message",
            }
        ],
    )


class ManifestTests(unittest.TestCase):
    def test_accepts_whitespace_in_hex(self):
        value = hello_mapping()
        value["shellcode_hex"] = "b8 3c 00 00 00\n0f 05"
        manifest = compiler.Manifest.from_mapping(value)
        self.assertEqual(manifest.shellcode, bytes.fromhex("b83c0000000f05"))

    def test_rejects_invalid_hex(self):
        value = hello_mapping()
        value["shellcode_hex"] = "not machine code"
        with self.assertRaisesRegex(compiler.CompileError, "non-hexadecimal"):
            compiler.Manifest.from_mapping(value)

    def test_rejects_entry_outside_payload(self):
        value = hello_mapping()
        value["entry_offset"] = len(bytes.fromhex(HELLO_HEX))
        with self.assertRaisesRegex(compiler.CompileError, "inside the payload"):
            compiler.Manifest.from_mapping(value)

    def test_rejects_elf_as_payload(self):
        value = hello_mapping()
        value["shellcode_hex"] = "7f454c4602010100"
        with self.assertRaisesRegex(compiler.CompileError, "already contains"):
            compiler.Manifest.from_mapping(value)

    def test_rejects_pe_and_macho_as_payload(self):
        pe = hello_mapping("x86_64-windows", "4d5a0000")
        macho = hello_mapping("x86_64-macos", "cffaedfe")
        with self.assertRaisesRegex(compiler.CompileError, "header"):
            compiler.Manifest.from_mapping(pe)
        with self.assertRaisesRegex(compiler.CompileError, "Mach-O"):
            compiler.Manifest.from_mapping(macho)

    def test_links_x86_branch_and_rip_relative_data(self):
        value = reloc_mapping(
            "x86_64-linux",
            [
                {"label": "entry", "kind": "code", "hex": "e900000000"},
                {"label": "dead", "kind": "code", "hex": "90"},
                {
                    "label": "target",
                    "kind": "code",
                    "hex": "488d0500000000",
                },
                {"label": "done", "kind": "code", "hex": "c3"},
                {"label": "message", "kind": "data", "hex": "6869"},
            ],
            [
                {"source": "entry", "kind": "x86_rel32", "target": "target"},
                {
                    "source": "target",
                    "kind": "x86_rip_rel32",
                    "target": "message",
                },
            ],
        )

        manifest = compiler.Manifest.from_mapping(value)

        self.assertEqual(manifest.shellcode[:5], bytes.fromhex("e901000000"))
        self.assertEqual(manifest.shellcode[6:13], bytes.fromhex("488d0501000000"))
        self.assertEqual(manifest.as_json(), value)

    def test_links_backward_x86_branch(self):
        value = reloc_mapping(
            "x86_64-linux",
            [
                {"label": "target", "kind": "code", "hex": "90"},
                {"label": "entry", "kind": "code", "hex": "e900000000"},
            ],
            [{"source": "entry", "kind": "x86_rel32", "target": "target"}],
        )

        manifest = compiler.Manifest.from_mapping(value)

        self.assertEqual(manifest.entry_offset, 1)
        self.assertEqual(manifest.shellcode, bytes.fromhex("90e9faffffff"))

    def test_rejects_bad_x86_relocation_opcode_and_placeholder(self):
        cases = (
            ("9000000000", "must end in E8/E9"),
            ("e901000000", "placeholder must be"),
        )
        for machine_code, message in cases:
            with self.subTest(machine_code=machine_code):
                value = reloc_mapping(
                    "x86_64-linux",
                    [
                        {"label": "entry", "kind": "code", "hex": machine_code},
                        {"label": "target", "kind": "code", "hex": "c3"},
                    ],
                    [
                        {
                            "source": "entry",
                            "kind": "x86_rel32",
                            "target": "target",
                        }
                    ],
                )
                with self.assertRaisesRegex(compiler.CompileError, message):
                    compiler.Manifest.from_mapping(value)

    def test_rejects_reused_or_unknown_fixup_labels(self):
        base_chunks = [
            {"label": "entry", "kind": "code", "hex": "e900000000"},
            {"label": "target", "kind": "code", "hex": "c3"},
        ]
        reused = reloc_mapping(
            "x86_64-linux",
            base_chunks,
            [
                {"source": "entry", "kind": "x86_rel32", "target": "target"},
                {"source": "entry", "kind": "x86_rel32", "target": "target"},
            ],
        )
        unknown = reloc_mapping(
            "x86_64-linux",
            base_chunks,
            [{"source": "entry", "kind": "x86_rel32", "target": "missing"}],
        )
        with self.assertRaisesRegex(compiler.CompileError, "more than one fixup"):
            compiler.Manifest.from_mapping(reused)
        with self.assertRaisesRegex(compiler.CompileError, "unknown target"):
            compiler.Manifest.from_mapping(unknown)

    def test_rejects_branch_to_data(self):
        value = reloc_mapping(
            "x86_64-linux",
            [
                {"label": "entry", "kind": "code", "hex": "e900000000"},
                {"label": "bytes", "kind": "data", "hex": "00"},
            ],
            [{"source": "entry", "kind": "x86_rel32", "target": "bytes"}],
        )

        with self.assertRaisesRegex(compiler.CompileError, "branch target must be"):
            compiler.Manifest.from_mapping(value)

    def test_links_aarch64_branch_and_adr(self):
        value = reloc_mapping(
            "aarch64-linux",
            [
                {"label": "entry", "kind": "code", "hex": "00000014"},
                {"label": "dead", "kind": "code", "hex": "1f2003d5"},
                {"label": "target", "kind": "code", "hex": "00000010"},
                {"label": "message", "kind": "data", "hex": "6869"},
            ],
            [
                {
                    "source": "entry",
                    "kind": "aarch64_branch26",
                    "target": "target",
                },
                {
                    "source": "target",
                    "kind": "aarch64_adr21",
                    "target": "message",
                },
            ],
        )

        manifest = compiler.Manifest.from_mapping(value)

        self.assertEqual(manifest.shellcode[:4], bytes.fromhex("02000014"))
        self.assertEqual(manifest.shellcode[8:12], bytes.fromhex("20000010"))

    def test_links_aarch64_conditional_test_and_literal_fixups(self):
        cases = (
            ("00000054", "aarch64_branch19", "40000054", "code", "c0035fd6"),
            ("00000036", "aarch64_branch14", "40000036", "code", "c0035fd6"),
            ("00000058", "aarch64_literal19", "20000058", "data", "78563412"),
        )
        for instruction, kind, expected, target_kind, target_hex in cases:
            with self.subTest(kind=kind):
                value = reloc_mapping(
                    "aarch64-linux",
                    [
                        {"label": "entry", "kind": "code", "hex": instruction},
                        {"label": "middle", "kind": "code", "hex": "1f2003d5"}
                        if target_kind == "code"
                        else {
                            "label": "target",
                            "kind": target_kind,
                            "hex": target_hex,
                        },
                        {"label": "target", "kind": target_kind, "hex": target_hex}
                        if target_kind == "code"
                        else {"label": "tail", "kind": "data", "hex": "00"},
                    ],
                    [{"source": "entry", "kind": kind, "target": "target"}],
                )

                manifest = compiler.Manifest.from_mapping(value)

                self.assertEqual(manifest.shellcode[:4], bytes.fromhex(expected))

    def test_links_arm_branch_and_negative_literal(self):
        branch = reloc_mapping(
            "arm-linux",
            [
                {"label": "entry", "kind": "code", "hex": "000000ea"},
                {"label": "dead1", "kind": "code", "hex": "0000a0e1"},
                {"label": "dead2", "kind": "code", "hex": "0000a0e1"},
                {"label": "target", "kind": "code", "hex": "1eff2fe1"},
            ],
            [{"source": "entry", "kind": "arm_branch24", "target": "target"}],
        )
        literal = reloc_mapping(
            "arm-linux",
            [
                {"label": "word", "kind": "data", "hex": "78563412"},
                {"label": "entry", "kind": "code", "hex": "00009fe5"},
            ],
            [{"source": "entry", "kind": "arm_literal12", "target": "word"}],
        )

        self.assertEqual(
            compiler.Manifest.from_mapping(branch).shellcode[:4],
            bytes.fromhex("010000ea"),
        )
        self.assertEqual(
            compiler.Manifest.from_mapping(literal).shellcode[4:8],
            bytes.fromhex("0c001fe5"),
        )

    def test_arm_linker_aligns_code_after_data(self):
        value = reloc_mapping(
            "aarch64-linux",
            [
                {"label": "byte", "kind": "data", "hex": "ff"},
                {"label": "entry", "kind": "code", "hex": "c0035fd6"},
            ],
        )

        manifest = compiler.Manifest.from_mapping(value)

        self.assertEqual(manifest.entry_offset, 4)
        self.assertEqual(manifest.shellcode, bytes.fromhex("ff000000c0035fd6"))

    def test_review_prompt_distrusts_candidate_branch_encodings(self):
        candidate = compiler.Manifest.from_mapping(hello_mapping())

        prompt = build_review_prompt("print hello", candidate, 1)

        self.assertIn("candidate below is untrusted", prompt)
        self.assertIn("instruction-boundary ledger", prompt)
        self.assertIn("supported fixup", prompt)
        self.assertIn("deterministic linker", prompt)
        self.assertIn("zero terminal dimensions", prompt)
        self.assertIn(candidate.shellcode.hex(), prompt)


class ElfTests(unittest.TestCase):
    def setUp(self):
        self.manifest = compiler.Manifest.from_mapping(hello_mapping())

    def test_elf_layout(self):
        image = compiler.build_elf(self.manifest)
        self.assertEqual(image[:4], b"\x7fELF")
        self.assertEqual(len(image), 120 + len(self.manifest.shellcode))
        self.assertEqual(struct.unpack_from("<H", image, 18)[0], 62)
        self.assertEqual(struct.unpack_from("<Q", image, 24)[0], 0x400078)
        self.assertEqual(struct.unpack_from("<Q", image, 32)[0], 64)
        self.assertEqual(struct.unpack_from("<I", image, 64)[0], 1)
        self.assertEqual(struct.unpack_from("<I", image, 68)[0], 5)
        self.assertEqual(
            struct.unpack_from("<Q", image, 96)[0], len(image)
        )
        self.assertEqual(image[120:], self.manifest.shellcode)

    def test_aarch64_elf64_layout(self):
        manifest = compiler.Manifest.from_mapping(
            hello_mapping("aarch64-linux", "1f2003d5")
        )
        image = compiler.build_executable(manifest)
        self.assertEqual(image[4], 2)
        self.assertEqual(struct.unpack_from("<H", image, 18)[0], 183)
        self.assertEqual(struct.unpack_from("<Q", image, 24)[0], 0x400078)
        self.assertEqual(image[120:], bytes.fromhex("1f2003d5"))

    def test_arm_elf32_layout(self):
        manifest = compiler.Manifest.from_mapping(
            hello_mapping("arm-linux", "0000a0e1")
        )
        image = compiler.build_executable(manifest)
        self.assertEqual(image[4], 1)
        self.assertEqual(struct.unpack_from("<H", image, 18)[0], 40)
        self.assertEqual(struct.unpack_from("<I", image, 24)[0], 0x10054)
        self.assertEqual(struct.unpack_from("<I", image, 36)[0], 0x05000000)
        self.assertEqual(image[84:], bytes.fromhex("0000a0e1"))

    def test_entry_offset_changes_entry_address(self):
        value = hello_mapping()
        value["entry_offset"] = 5
        image = compiler.build_elf(compiler.Manifest.from_mapping(value))
        self.assertEqual(struct.unpack_from("<Q", image, 24)[0], 0x40007D)

    @unittest.skipUnless(
        sys.platform == "linux" and platform.machine().lower() in {"x86_64", "amd64"},
        "requires Linux x86-64",
    )
    def test_generated_elf_executes(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "hello"
            compiler.write_executable(
                output, compiler.build_elf(self.manifest), force=False
            )
            completed = subprocess.run([output], capture_output=True, check=False)
            self.assertEqual(completed.returncode, 0)
            self.assertEqual(completed.stdout, b"hello world")
            self.assertEqual(completed.stderr, b"")

    def test_refuses_overwrite_without_force(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "program"
            output.write_bytes(b"existing")
            with self.assertRaisesRegex(compiler.CompileError, "already exists"):
                compiler.write_executable(output, b"replacement", force=False)
            self.assertEqual(output.read_bytes(), b"existing")


class PeTests(unittest.TestCase):
    def setUp(self):
        self.manifest = compiler.Manifest.from_mapping(
            hello_mapping("x86_64-windows", "c3")
        )

    def test_pe32_plus_layout(self):
        image = compiler.build_executable(self.manifest)
        self.assertEqual(image[:2], b"MZ")
        self.assertEqual(struct.unpack_from("<I", image, 0x3C)[0], 0x80)
        self.assertEqual(image[0x80:0x84], b"PE\x00\x00")
        self.assertEqual(struct.unpack_from("<H", image, 0x84)[0], 0x8664)
        self.assertEqual(struct.unpack_from("<H", image, 0x98)[0], 0x20B)
        self.assertEqual(struct.unpack_from("<I", image, 0xA8)[0], 0x1000)
        self.assertEqual(struct.unpack_from("<Q", image, 0xB0)[0], 0x140000000)
        self.assertEqual(image[0x188:0x190], b".text\x00\x00\x00")
        self.assertEqual(struct.unpack_from("<I", image, 0x19C)[0], 0x200)
        self.assertEqual(image[0x200], 0xC3)
        self.assertEqual(len(image), 0x400)

    def test_pe_entry_offset(self):
        value = hello_mapping("x86_64-windows", "90c3")
        value["entry_offset"] = 1
        image = compiler.build_pe(compiler.Manifest.from_mapping(value))
        self.assertEqual(struct.unpack_from("<I", image, 0xA8)[0], 0x1001)


class MachOTests(unittest.TestCase):
    def test_x86_64_macho_layout(self):
        manifest = compiler.Manifest.from_mapping(
            hello_mapping("x86_64-macos", "c3")
        )
        image = compiler.build_executable(manifest)
        self.assertEqual(struct.unpack_from("<I", image, 0)[0], 0xFEEDFACF)
        self.assertEqual(struct.unpack_from("<I", image, 4)[0], 0x01000007)
        self.assertEqual(struct.unpack_from("<I", image, 12)[0], 2)
        self.assertEqual(struct.unpack_from("<I", image, 16)[0], 5)
        self.assertEqual(struct.unpack_from("<I", image, 20)[0], 304)
        self.assertEqual(image[0x1000], 0xC3)

    def test_aarch64_macho_layout(self):
        manifest = compiler.Manifest.from_mapping(
            hello_mapping("aarch64-macos", "c0035fd6")
        )
        image = compiler.build_macho(manifest)
        self.assertEqual(struct.unpack_from("<I", image, 4)[0], 0x0100000C)
        self.assertEqual(image[0x1000:], bytes.fromhex("c0035fd6"))


class TargetTests(unittest.TestCase):
    def test_aliases(self):
        self.assertEqual(
            compiler.resolve_target("win32", "amd64").manifest_name,
            "x86_64-windows",
        )
        self.assertEqual(
            compiler.resolve_target("darwin", "arm64").manifest_name,
            "aarch64-macos",
        )

    def test_rejects_unsupported_combination(self):
        with self.assertRaisesRegex(compiler.CompileError, "unsupported target"):
            compiler.resolve_target("windows", "arm")


class ThrobberTests(unittest.TestCase):
    def test_renders_and_clears_line(self):
        stream = io.StringIO()

        with Throbber("Progress", stream=stream, enabled=True, interval=60):
            pass

        output = stream.getvalue()
        self.assertTrue(output.startswith("\r| Progress"))
        self.assertTrue(output.endswith("\r          \r"))

    def test_disabled_throbber_is_silent(self):
        stream = io.StringIO()

        with Throbber("Progress", stream=stream, enabled=False):
            pass

        self.assertEqual(stream.getvalue(), "")


class TerminalFlowWriterTests(unittest.TestCase):
    def render(self, chunks, width=28):
        stream = io.StringIO()
        writer = TerminalFlowWriter(
            stream=stream, prefix="progress: ", width=lambda: width
        )
        for chunk in chunks:
            writer.write(chunk)
        writer.finish()
        return stream.getvalue()

    def test_wraps_and_indents_to_terminal_width(self):
        output = self.render(
            ["Encoding the syscall sequence and checking every offset."], width=28
        )

        lines = output.splitlines()
        self.assertTrue(lines[0].startswith("progress: "))
        self.assertTrue(all(display_width(line) <= 28 for line in lines))
        self.assertTrue(all(line.startswith("          ") for line in lines[1:]))

    def test_chunk_boundaries_do_not_change_flow(self):
        text = "Encoding the syscall sequence and checking every offset."

        whole = self.render([text])
        chunked = self.render(["Encod", "ing the sys", "call sequence ", "and checking every offset."])

        self.assertEqual(chunked, whole)

    def test_preserves_paragraph_breaks(self):
        output = self.render(["First paragraph.\n\nSecond paragraph."])

        self.assertIn("paragraph.\n\n          Second", output)

    def test_omits_indent_when_terminal_is_too_narrow(self):
        output = self.render(["supercalifragilistic"], width=8)

        self.assertTrue(all(display_width(line) <= 8 for line in output.splitlines()))
        self.assertNotIn("progress:", output)


class ApiResponseTests(unittest.TestCase):
    def test_extracts_responses_api_text(self):
        response = {
            "output": [
                {
                    "type": "message",
                    "content": [
                        {"type": "output_text", "text": json.dumps(hello_mapping())}
                    ],
                }
            ]
        }
        text = compiler.extract_response_text(response)
        self.assertEqual(json.loads(text), hello_mapping())

    def test_surfaces_refusal(self):
        response = {
            "output": [
                {
                    "type": "message",
                    "content": [{"type": "refusal", "refusal": "no"}],
                }
            ]
        }
        with self.assertRaisesRegex(compiler.CompileError, "refused"):
            compiler.extract_response_text(response)

    def test_surfaces_incomplete_response(self):
        response = {
            "status": "incomplete",
            "incomplete_details": {"reason": "max_output_tokens"},
        }
        with self.assertRaisesRegex(compiler.CompileError, "max_output_tokens"):
            compiler.extract_response_text(response)

    def test_quota_error_explains_api_billing(self):
        error_body = json.dumps(
            {
                "error": {
                    "message": "You exceeded your current quota",
                    "type": "insufficient_quota",
                    "code": "insufficient_quota",
                }
            }
        ).encode("utf-8")
        http_error = urllib.error.HTTPError(
            "https://example.invalid/v1/responses",
            429,
            "Too Many Requests",
            {},
            io.BytesIO(error_body),
        )

        with mock.patch.object(
            compiler_api.urllib.request, "urlopen", side_effect=http_error
        ):
            with self.assertRaises(compiler.CompileError) as raised:
                compiler.request_manifest(
                    "write hello world",
                    target=compiler.TARGETS[("linux", "x86_64")],
                    api_key="test-key",
                    model="test-model",
                    api_base="https://example.invalid/v1",
                    timeout=10,
                    reasoning_effort="high",
                    max_payload=1024,
                )

        message = str(raised.exception)
        self.assertIn("ChatGPT subscriptions and API billing are separate", message)
        self.assertIn("/settings/organization/billing/overview", message)
        self.assertIn("couple of minutes", message)

    def test_request_uses_responses_api_and_schema(self):
        api_response = {
            "output": [
                {
                    "type": "message",
                    "content": [
                        {
                            "type": "output_text",
                            "text": json.dumps(reloc_hello_mapping()),
                        }
                    ],
                }
            ]
        }
        fake_response = io.BytesIO(json.dumps(api_response).encode("utf-8"))
        with mock.patch.object(
            compiler_api.urllib.request, "urlopen", return_value=fake_response
        ) as urlopen:
            manifest = compiler.request_manifest(
                "write hello world",
                target=compiler.TARGETS[("linux", "x86_64")],
                api_key="test-key",
                model="test-model",
                api_base="https://example.invalid/v1/",
                timeout=10,
                reasoning_effort="high",
                max_payload=1024,
            )

        request = urlopen.call_args.args[0]
        body = json.loads(request.data)
        self.assertEqual(request.full_url, "https://example.invalid/v1/responses")
        self.assertEqual(request.get_header("Authorization"), "Bearer test-key")
        self.assertEqual(body["model"], "test-model")
        self.assertEqual(
            body["text"]["format"]["schema"]["properties"]["architecture"]["enum"],
            ["x86_64-linux"],
        )
        schema = body["text"]["format"]["schema"]
        self.assertIn("chunks", schema["properties"])
        self.assertIn("fixups", schema["properties"])
        self.assertNotIn("shellcode_hex", schema["properties"])
        self.assertFalse(body["store"])
        self.assertNotIn("stream", body)
        self.assertEqual(body["text"]["format"]["type"], "json_schema")
        instructions = body["instructions"]
        self.assertIn("readable and executable but not writable", instructions)
        self.assertIn("symbolic labels and exact instruction sizes", instructions)
        self.assertIn("Never encode a PC-relative branch", instructions)
        self.assertIn("linker validates opcode forms", instructions)
        self.assertIn("restore that exact state on every exit", instructions)
        self.assertIn("SYSCALL clobbers RCX and R11", instructions)
        self.assertEqual(manifest.shellcode, bytes.fromhex(HELLO_HEX))

    def test_streams_reasoning_summary_and_returns_completed_response(self):
        completed_response = {
            "status": "completed",
            "output": [
                {
                    "type": "message",
                    "content": [
                        {
                            "type": "output_text",
                            "text": json.dumps(reloc_hello_mapping()),
                        }
                    ],
                }
            ],
        }
        events = [
            {
                "type": "response.reasoning_summary_text.delta",
                "delta": "Encoding ",
            },
            {
                "type": "response.reasoning_summary_text.delta",
                "delta": "the syscall sequence.",
            },
            {"type": "response.completed", "response": completed_response},
        ]
        stream_body = "".join(
            f"event: {event['type']}\ndata: {json.dumps(event)}\n\n"
            for event in events
        ).encode("utf-8")
        fake_response = io.BytesIO(stream_body)
        reasoning_deltas = []

        with mock.patch.object(
            compiler_api.urllib.request, "urlopen", return_value=fake_response
        ) as urlopen:
            manifest = compiler.request_manifest(
                "write hello world",
                target=compiler.TARGETS[("linux", "x86_64")],
                api_key="test-key",
                model="test-model",
                api_base="https://example.invalid/v1",
                timeout=10,
                reasoning_effort="high",
                max_payload=1024,
                on_reasoning_delta=reasoning_deltas.append,
            )

        body = json.loads(urlopen.call_args.args[0].data)
        self.assertTrue(body["stream"])
        self.assertEqual(body["reasoning"]["summary"], "auto")
        self.assertEqual(reasoning_deltas, ["Encoding ", "the syscall sequence."])
        self.assertEqual(manifest.shellcode, bytes.fromhex(HELLO_HEX))

    def test_rejects_stream_without_terminal_response(self):
        event = {
            "type": "response.reasoning_summary_text.delta",
            "delta": "Still working",
        }
        stream = io.BytesIO(f"data: {json.dumps(event)}\n\n".encode("utf-8"))

        with self.assertRaisesRegex(compiler.CompileError, "without a completed"):
            compiler_api.read_streaming_response(stream, lambda delta: None)

    def test_timeout_error_recommends_a_larger_limit(self):
        errors = [TimeoutError("timed out"), urllib.error.URLError(TimeoutError())]
        for transport_error in errors:
            with self.subTest(transport_error=transport_error):
                with mock.patch.object(
                    compiler_api.urllib.request,
                    "urlopen",
                    side_effect=transport_error,
                ):
                    with self.assertRaises(compiler.CompileError) as raised:
                        compiler.request_manifest(
                            "write hello world",
                            target=compiler.TARGETS[("linux", "x86_64")],
                            api_key="test-key",
                            model="test-model",
                            api_base="https://example.invalid/v1",
                            timeout=12,
                            reasoning_effort="high",
                            max_payload=1024,
                        )

                message = str(raised.exception)
                self.assertIn("timed out after 12 seconds", message)
                self.assertIn("--timeout 1800", message)


class CliTests(unittest.TestCase):
    def test_default_timeout_allows_long_reasoning(self):
        args = compiler_cli.build_parser().parse_args(["print hello"])

        self.assertEqual(args.timeout, 900)
        self.assertEqual(args.verify_passes, 1)

    def test_prompt_generation_runs_independent_review(self):
        manifest = compiler.Manifest.from_mapping(hello_mapping())
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "reviewed"
            with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
                with mock.patch.object(
                    compiler_cli,
                    "request_manifest",
                    side_effect=[manifest, manifest],
                ) as request_manifest:
                    result = compiler_cli.main(
                        ["print hello", "-o", str(output), "--quiet"]
                    )

        self.assertEqual(result, 0)
        self.assertEqual(request_manifest.call_count, 2)
        self.assertEqual(request_manifest.call_args_list[0].args[0], "print hello")
        review_prompt = request_manifest.call_args_list[1].args[0]
        self.assertIn("INDEPENDENT BYTECODE VERIFICATION PASS 1", review_prompt)

    def test_missing_api_key_explains_how_to_configure_it(self):
        env = os.environ.copy()
        env.pop("OPENAI_API_KEY", None)
        completed = subprocess.run(
            [sys.executable, "-m", "prompt2exe", "print hello"],
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )

        self.assertEqual(completed.returncode, 1)
        self.assertIn("https://platform.openai.com/api-keys", completed.stderr)
        self.assertIn("export OPENAI_API_KEY=", completed.stderr)
        self.assertIn("do not commit or share it", completed.stderr)

    def test_offline_manifest_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "hello.json"
            output = root / "hello"
            manifest.write_text(json.dumps(hello_mapping()), encoding="utf-8")
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "prompt2exe",
                    "--manifest",
                    str(manifest),
                    "-o",
                    str(output),
                    "--quiet",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(output.exists())
            self.assertEqual(output.read_bytes()[:4], b"\x7fELF")

    def test_rejects_manifest_output_collision(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "hello.json"
            output = root / "collision"
            manifest.write_text(json.dumps(hello_mapping()), encoding="utf-8")
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "prompt2exe",
                    "--manifest",
                    str(manifest),
                    "-o",
                    str(output),
                    "--manifest-out",
                    str(output),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 1)
            self.assertIn("must be different", completed.stderr)
            self.assertFalse(output.exists())

    def test_partial_target_constraint_uses_manifest_architecture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "arm64.json"
            output = root / "arm64"
            manifest.write_text(
                json.dumps(hello_mapping("aarch64-linux", "1f2003d5")),
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "prompt2exe",
                    "--manifest",
                    str(manifest),
                    "--os",
                    "linux",
                    "-o",
                    str(output),
                    "--quiet",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(struct.unpack_from("<H", output.read_bytes(), 18)[0], 183)

    def test_rejects_manifest_target_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "arm64.json"
            output = root / "program"
            manifest.write_text(
                json.dumps(hello_mapping("aarch64-linux", "1f2003d5")),
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "prompt2exe",
                    "--manifest",
                    str(manifest),
                    "--arch",
                    "x64",
                    "-o",
                    str(output),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 1)
            self.assertIn("does not match", completed.stderr)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
