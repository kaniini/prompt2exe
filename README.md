## prompt2exe

`prompt2exe` asks an OpenAI model for a validated JSON shellcode manifest
and wraps the returned bytes in a target-native executable container. It uses
the Responses API directly through Python's standard library, so it has no
package dependencies.

```sh
# Create a key at https://platform.openai.com/api-keys, then:
export OPENAI_API_KEY='your-api-key'
python3 -m prompt2exe \
  'print hello world and exit successfully' -o generated
./generated
```

API usage is, unfortunately, billed separately from ChatGPT subscriptions.
Configure API billing or add credits in the
[API billing overview](https://platform.openai.com/settings/organization/billing/overview).

Supported targets:

| OS      | Architecture        | Container       |
| ------- | ------------------- | --------------- |
| Linux   | `x86_64`            | ELF64           |
| Linux   | `aarch64` / `arm64` | ELF64           |
| Linux   | `arm` / `arm32`     | ELF32 Arm EABI5 |
| Windows | `x86_64` / `x64`    | PE32+           |
| macOS   | `x86_64`            | Mach-O 64       |
| macOS   | `aarch64` / `arm64` | Mach-O 64       |

```sh
python3 -m prompt2exe --os linux --arch arm64 \
  'print hello using Linux syscalls' -o hello-arm64

python3 -m prompt2exe --os windows --arch x64 \
  'write hello to the console and exit' -o hello.exe

python3 -m prompt2exe --os macos --arch arm64 \
  'print hello using Darwin syscalls' -o hello-macos
```

Windows PE files deliberately have no import table; their shellcode must
resolve Win32 APIs through the PEB and export tables. Apple Silicon may require
ad-hoc signing before execution: `codesign --sign - hello-macos`.

The default model can be changed with `--model` or `PROMPT2EXE_MODEL`. The API
endpoint can be changed with `--api-base` or `OPENAI_BASE_URL`.
During interactive requests, `prompt2exe` presents the model's supported
reasoning summary as a progress stream on standard error. OpenAI does not
expose raw reasoning tokens. `--quiet` disables both this stream and the
initial throbber.
The API socket timeout defaults to 15 minutes for complex reasoning requests;
use `--timeout SECONDS` to increase it further.

Prompt builds use one independent model verification pass by default. The
reviewer decodes the candidate bytes, recomputes branch targets, and may replace
an implementation it cannot prove correct. This doubles model requests and
token use. Use `--verify-passes 0` for the original single-call behavior, or up
to `--verify-passes 3` for especially difficult programs.

An offline manifest mode makes byte wrapping deterministic and does not require
network access:

```sh
python3 -m prompt2exe \
  --manifest hello.manifest.json -o generated
```

The compiler validates target compatibility, hexadecimal encoding, entry
bounds and alignment, payload size, nested executable headers, base-address
alignment, and overwrite behavior. It does not claim that arbitrary generated
machine code is semantically correct.
Generated files are never executed unless `--run` is supplied explicitly; use
that option only in an appropriately isolated environment.

The implementation is split by responsibility under `prompt2exe/`:
target definitions, manifest validation, API transport, CLI handling, output
I/O, and independent ELF, PE, and Mach-O emitters. Invoke it with
`python3 -m prompt2exe --help`.
