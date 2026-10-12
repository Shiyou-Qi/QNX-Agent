# @local/uefi-mcp — Qi-NX UEFI MCP server

Wraps the Qi-NX reverse-engineering toolkit as MCP tools so a DSH agent can call
them directly instead of shelling out to Python scripts.

**by Qi-NX-Agent, Copyright Qi-NX.**

---

## Tools

All tools are published under the `uefi` server name, so the model sees
`mcp__uefi__<tool>`. Every tool returns JSON.

| Tool | Arguments | Returns |
|---|---|---|
| `tool_status` | — | which Python modules and external binaries actually exist here, plus the resolved script directories |
| `walk_fv` | `image`, `extract_dir?`, `max_files?` | firmware volumes, FFS files, sections; with `extract_dir`, writes every PE32/TE payload |
| `extract_vss` | `image`, `out_dir`, `raw_scan?`, `size_cap?` | candidate NVRAM stores, each validated and carved to a file |
| `parse_vss` | `image`, `variable?` | decoded variables with attributes and sensitive flags |
| `list_smi` | `image`, `guids?`, `include_dxe?`, `extract_dir?` | SMM/MM modules with EDK2 dispatch and communication markers |
| `uefi_firmware_parse` | `image`, `max_objects?` | decompression-aware parse via the `uefi-firmware` library |
| `binwalk_scan` | `image` | magic/compression offsets — binwalk when installed, otherwise the built-in scanner |
| `uefitool_extract` | `image`, `out_dir` | shells out to UEFIExtract; a clear error when it is absent |
| `lief_info` | `target`, `sections?`, `imports?`, `exports?`, `relocs?` | PE/ELF/Mach-O triage |
| `yara_scan` | `target`, `rules?`, `max_matches?` | built-in triage ruleset or your own rules |
| `pack_detect` | `target` | packer/protector verdict with a confidence note |

Broken or missing prerequisites never produce a fake success: tools return
`{"error": "..."}` plus a `hint` or `fallback` field naming the working
alternative. Call `tool_status` first to see what this host actually has.

## Recommended flow

```
tool_status                              # what is available here?
binwalk_scan image.bin                   # container + compression triage
walk_fv image.bin extract_dir=out/       # FV/FFS/section inventory + PE32 dumps
lief_info out/.../Driver.pe32 sections=true
extract_vss image.bin out_dir=vss/       # only if a store is present
parse_vss vss/vss_00_....bin
list_smi image.bin guids=guids.csv       # Ring -2 modules
```

Prefer `walk_fv` over `uefi_walk.py`: `walk_fv` parses the PI structures directly
(honouring `HeaderLength` and `EFI_FFS_FILE_HEADER2`) and extracts sections.
`uefi_walk.py` remains as the no-dependency coarse fallback.

---

## Wiring

The server is launched by one `@deepseek-ai/dsh-mcp-client` row. The versioned
[`cordis.patch.yml`](cordis.patch.yml) carries **no machine-specific paths** — it
only declares a portable default:

```yaml
- insert:
    - id: uefi-mcp
      name: '@deepseek-ai/dsh-mcp-client'
      config:
        serverName: uefi
        transport: stdio
        command: !!js process.env.QINX_PYTHON || 'python'
        args: ['dsh-uefi-mcp/server/uefi_mcp_server.py']
        cwd: !!js process.env.QINX_WORKSPACE || '.'
        toolCallTimeoutMs: 120000
        failOnStartupError: false
```

Two values may need pointing at your machine, because the default assumes a
`python` on `PATH` that has `mcp`, and DSH's bundled runtime usually is not on
`PATH`:

| Value | Default | Override with |
|---|---|---|
| `command` | `python` on `PATH` | `QINX_PYTHON`, or the profile patch below |
| `cwd` | `.` | `QINX_WORKSPACE`, or the profile patch below |

**Recommended:** leave the bundle alone and override the row in your own profile
patch (`$DSH_HOME/profiles/<profile>/cordis.patch.yml`), which is not versioned
with this bundle. A profile patch addresses the row by id and its `config`
replaces the bundle's wholesale:

```yaml
- id: uefi-mcp
  name: "@deepseek-ai/dsh-mcp-client"
  config:
    serverName: uefi
    transport: stdio
    command: '/absolute/path/to/python'
    args: ['/absolute/path/to/dsh-uefi-mcp/server/uefi_mcp_server.py']
    cwd: '/absolute/path/to/workspace'
    toolCallTimeoutMs: 120000
    failOnStartupError: false
```

`failOnStartupError: false` keeps DSH startable if the server breaks; the failure
is logged and no tools appear. Set it to `true` if you would rather have
activation rejected loudly.

### Host plane vs preset plane

This bundle mounts the client on the **Host plane**, so `mcp__uefi__*` is
available to every preset. That is the documented shape for a configuration-only
bundle and it is verified working.

If you would rather scope the tools to the Firmware/UEFI preset only, move the
`uefi-mcp` row into that preset's `plugins` list in
[`../dsh-uefi-preset/cordis.patch.yml`](../dsh-uefi-preset/cordis.patch.yml) and
uninstall this bundle. **Do not do both**: two `mcp-client` rows sharing
`serverName: uefi` collide and the second fails to load.

### Locating the scripts

`server/uefi_mcp_server.py` resolves the Qi-NX skill script trees from, in order:

1. the `QINX_FW_SCRIPTS` / `QINX_RE_SCRIPTS` environment variables
2. an optional `_paths.local.json` beside the bundle (git-ignored; not shipped)
3. **the workspace that contains the bundle**, derived from the server's own path
   — the server sits at `<workspace>/dsh-uefi-mcp/server/uefi_mcp_server.py`, so
   the workspace is two levels up

Step 3 is the normal case and needs no configuration, which is what lets this
bundle stay free of absolute paths. Steps 1 and 2 exist for the case where the
bundle lives outside the workspace it serves. If a resolved directory does not
exist, the server names it on stderr rather than failing silently.

---

## Protocol notes

- Built on the official `mcp` Python SDK (`mcp.server.mcpserver.MCPServer`; in
  mcp 2.x `FastMCP` was renamed to `MCPServer`).
- The handshake currently settles on **2025-11-25**. The SDK's
  `LATEST_PROTOCOL_VERSION` is 2026-07-28 but its server side answers
  2025-11-25, and the DSH MCP client documents falling back to supported legacy
  revisions. Tool registration is unaffected.
- stdio means **nothing may be written to stdout except JSON-RPC**. All server
  diagnostics go to stderr; keep it that way when editing.

## Testing

```powershell
& "<DSH python>" tests/test_mcp_protocol.py tests/artifacts/fixture.bin
```

Speaks newline-delimited JSON-RPC directly (no client SDK), so it verifies the
wire behaviour DSH itself depends on. Run `tests/verify_all.py` for the full
suite including the parsers.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| no `mcp__uefi__*` tools appear | `mcp` missing from the configured `command` interpreter. Confirm with `<python> -c "import mcp"`. |
| tools listed but calls fail | the server process died; check the DSH log for `qinx-uefi-mcp` stderr lines. |
| `serverName "uefi" is already in use` | two mcp-client rows share the name — use one wiring mode only. |
| `lief_info`/`yara_scan`/`pack_detect` return an error | the Python package is missing; the error names it. |
| `binwalk_scan` says `internal-signature-scan` | binwalk is not installed; this is the documented fallback, not a failure. |
| large images return few FVs | `walk_fv` caps the response at 8 firmware volumes and notes the truncation; narrow the image first. |

---

*by Qi-NX-Agent, Copyright Qi-NX.*
