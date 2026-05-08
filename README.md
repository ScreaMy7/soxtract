# soxtract

[![PyPI](https://img.shields.io/pypi/v/soxtract)](https://pypi.org/project/soxtract/)
[![Python](https://img.shields.io/pypi/pyversions/soxtract)](https://pypi.org/project/soxtract/)
[![CI](https://github.com/ScreaMy7/soxtract/actions/workflows/ci.yml/badge.svg)](https://github.com/ScreaMy7/soxtract/actions)

Dynamically extract native `.so` libraries from running Android applications using Frida.
Extracted files are automatically repaired into valid ELF binaries ready for analysis in
Ghidra, Binary Ninja, IDA Pro, or similar tools.

---

## How it works

soxtract injects a Frida agent into the target process and captures native libraries
through four complementary methods:

1. **Initial enumeration** — dumps all `.so` files already loaded at attach time
2. **dlopen hooks** — intercepts `dlopen` and `android_dlopen_ext` to catch libraries loaded at runtime
3. **Periodic memory scan** — scans executable memory for ELF magic bytes every 5 seconds, catching libraries loaded through custom loaders
4. **Disk fallback** — if a memory read fails completely, reads the library directly from the device filesystem

After extraction, each dump is validated and repaired with a built-in ELF fixer before
being saved as a proper `.so` file alongside a JSON metadata sidecar.

---

## Requirements

- Rooted Android device (or emulator) with [frida-server](https://github.com/frida/frida/releases) running
- USB debugging enabled, device visible to `adb`
- Python 3.10+

---

## Installation

### From PyPI (recommended)

```bash
pip install soxtract
```

The compiled Frida agent is bundled — no Node.js required.

### From source

```bash
git clone https://github.com/ScreaMy7/soxtract.git
cd soxtract

# Build the Frida agent (requires Node.js 18+)
cd agent && npm install && npm run build && cd ..

pip install -e .
```

---

## Usage

```bash
# Attach to a running app
soxtract com.example.app

# Spawn the app from scratch (captures libs loaded at startup)
soxtract com.example.app --spawn

# Attach by PID
soxtract 1234

# Stop automatically after 60 seconds
soxtract com.example.app --timeout 60

# Save to a custom directory
soxtract com.example.app --output-dir /tmp/dumps
```

---

## Output structure

```
soxtract_out/
└── com.example.app/
    └── 20260426_143022/
        ├── libs/               ← repaired .so files + metadata
        │   ├── libfoo_1b2c3d00.so
        │   ├── libfoo_1b2c3d00.meta.json
        │   ├── libbar_2c3d4e00.so
        │   └── libbar_2c3d4e00.meta.json
        └── raw/                ← original memory dumps (backup)
            ├── libfoo_1b2c3d00.so.raw
            └── libbar_2c3d4e00.so.raw
```

File naming format: `{library_name}_{lower_32_bits_of_base_address}.so`

Each `.meta.json` sidecar records:

```json
{
  "library_name": "libfoo.so",
  "base_address": "0x7a1b2c3d00",
  "size_bytes": 2097152,
  "extraction_method": "dlopen_hook",
  "timestamp_utc": "2026-04-26T14:30:22Z",
  "package": "com.example.app",
  "elf_valid": true,
  "elf_bitness": 64,
  "elf_abi": "aarch64",
  "elf_repaired": true,
  "repair_changes": ["ph[1]: p_offset 0x0 → 0x6000", "zeroed e_shnum/e_shstrndx"]
}
```

---

## CLI options

| Flag | Default | Description |
|---|---|---|
| `--output-dir DIR` | `soxtract_out` | Root directory for output |
| `--spawn` | off | Spawn the app instead of attaching to a running process |
| `--timeout S` | `0` (unlimited) | Stop after N seconds |
| `--no-fix` | off | Skip ELF repair; save raw memory dump as-is |
| `--chunk-size KB` | `256` | Memory read chunk size |
| `--scan-interval MS` | `5000` | How often to scan memory for new libraries |
| `--loader-delay MS` | `250` | Delay after `dlopen` returns before reading the new module |
| `--retries N` | `3` | Memory read retry attempts before falling back to disk |
| `--config FILE` | — | Load settings from a TOML file |
| `--log-level LEVEL` | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |

---

## Configuration file

Copy `config.example.toml` and pass it with `--config`:

```bash
soxtract com.example.app --config my_config.toml
```

```toml
[soxtract]
chunk_size     = 262144   # bytes
scan_interval  = 5000     # ms
loader_delay   = 250      # ms
retries        = 3
retry_backoff_ms = 500
fix_elf        = true
spawn          = false
timeout        = 0
log_level      = "INFO"
```

CLI flags override config file values.

---

## ELF repair

Memory-dumped `.so` files have incorrect program-header file offsets (`p_offset`) because
the runtime layout does not match the on-disk layout. soxtract repairs this automatically:

- For each program header segment: `p_offset = p_vaddr − min(PT_LOAD p_vaddr)`
- Section header table info is zeroed out if absent (Android strips it from memory)
- The repaired file is validated before saving; if repair fails, the raw dump is kept

Use `--no-fix` to skip repair and save the raw dump directly.

---

## Known limitations

| Scenario | Behaviour |
|---|---|
| Packed / encrypted `.so` | Memory content differs from the original file. The dump is saved as-is; the meta JSON notes it as a possible packed library. |
| Custom native loaders | If a library is mapped anonymously (no path), the disk fallback is skipped and only the in-memory content is captured. |
| Very large libraries (>100 MB) | Transfer is slow due to Frida's message channel. Increase `--chunk-size` to reduce overhead. |
| Non-rooted device | Not supported — `frida-server` requires root to inject into arbitrary processes. |

---

## Project structure

```
soxtract/
├── soxtract/
│   ├── cli.py           # Entry point and argument parsing
│   ├── config.py        # Configuration (CLI + TOML merge)
│   ├── session.py       # Frida session lifecycle
│   ├── extractor.py     # Message dispatch, chunk reassembly, finalization
│   ├── elf_validator.py # ELF header inspection (no external deps)
│   ├── elf_fixer.py     # In-house ELF memory-dump repair
│   ├── metadata.py      # JSON sidecar model
│   └── dedup.py         # Deduplication by (name, base_address)
├── agent/
│   ├── src/
│   │   ├── index.ts     # Agent entry point + RPC exports
│   │   ├── reader.ts    # Chunked memory reader with retry + disk fallback
│   │   ├── scanner.ts   # Incremental memory scanner
│   │   ├── modules.ts   # Initial enumeration + dlopen hooks
│   │   ├── config.ts    # Runtime-configurable agent settings
│   │   └── types.ts     # Shared message protocol types
│   └── dist/
│       └── agent.js     # Compiled agent (run `npm run build` to regenerate)
├── tests/
│   ├── test_elf_validator.py
│   └── test_elf_fixer.py
├── config.example.toml
└── pyproject.toml
```

---

## Running tests

```bash
python3 -m pytest tests/
```

---

## Publishing a new release

```bash
# 1. Bump version in pyproject.toml
# 2. If agent changed, rebuild and copy:
cd agent && npm run build && cp dist/agent.js ../soxtract/agent.js && cd ..
# 3. Commit, tag and push
git add -A && git commit -m "release: v0.x.0"
git tag v0.x.0 && git push origin main --tags
# 4. Build and upload to PyPI
rm -rf dist/
python -m hatchling build
twine upload dist/* --username __token__ --password YOUR_PYPI_TOKEN
```
