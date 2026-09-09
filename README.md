# dsh-permission-matrix — a permission matrix plugin for DeepSeek Harness

English | [中文](README.zh.md)

DSH bundles its sandbox mode and approval policy into a few fixed presets. This plugin splits them into **two independent axes** and recombines them:

- **Sandbox (write boundary)**: workspace read-only / workspace read-write / whole-computer read-write
- **Approval**: human / auto-approve / auto risk-classify / auto-deny

That yields **9 switchable execution types**, plus two defaults: a **global default** for ordinary sessions and a separate **LLM-robot default** for social-channel sessions (QQ / WeChat / WeCom / Telegram …).

> Replaces the single `auto` preset from `dsh-auto-classifier`, keeping its rule + LLM-judge + hard-deny approach while turning the preset table into a full matrix.

---

## The 9 execution types

| # | Preset id | Label | Sandbox | Approval |
|---|---|---|---|---|
| 1 | `ro-human` | Workspace read-only + human | read-only | ask |
| 2 | `ro-deny` | Workspace read-only + auto-deny | read-only | never |
| 3 | `ww-human` | Workspace read-write + human | workspace-write | ask |
| 4 | `ww-classify` | Workspace read-write + auto risk-classify | workspace-write | ask |
| 5 | `ww-deny` | Workspace read-write + auto-deny | workspace-write | never |
| 6 | `fa-human` | Whole-computer read-write + human | danger-full-access | ask |
| 7 | `fa-deny` | Whole-computer read-write + auto-deny | danger-full-access | never |
| 8 | `fa-auto` | Whole-computer read-write + auto-approve | danger-full-access | ask |
| 9 | `fa-classify` | Whole-computer read-write + auto risk-classify | danger-full-access | ask |

Three of the 12 theoretical combinations are duplicates and were dropped: auto-approve behaves identically under every sandbox (the sandbox denial is simply auto-granted), and risk-classify under read-only matches its workspace-read-write form.

## The key design point

`APPROVAL_POLICIES` only has `ask` and `never`. So:

| Approval tier | Value written in the preset table | Implemented by |
|---|---|---|
| human | `ask` | the browser answerer (plugin stays out) |
| auto-approve | `ask` | **this plugin** returns `allowed-once` on `approval/request` |
| auto risk-classify | `ask` | **this plugin** decides on `tools/pre-execute` + `approval/request` |
| auto-deny | `never` | DSH itself (plugin stays out) |

The plugin routes by the **current session's preset id** via a `takeover` table; presets not listed are left untouched (the plugin calls `next()` throughout).

## Risk classification

1. **HARD deny** → rejected; **a human cannot override it** ("allow" and "ask" cannot lift it).
2. **In-workspace structural pass** for write/edit/read whose target resolves inside the session workspace (protected targets excepted: `~/.dsh`, credentials, `.git/config|hooks`).
3. **Allow rules** (routine git, package managers, language runtimes, PowerShell cmdlets…).
4. **LLM judge** (toggleable) — semantic verdict; empty model means "follow the current session model".
5. **Mid-risk policy** (one of three): `deny` (default) / `allow` / `ask` (escalate to a human — works under full access too, via `tools/pre-execute` returning `{kind:'ask'}`).

The hard-deny list is **read-only** in the settings page: it cannot be edited, so no configuration can bypass "a human cannot approve this".

## Global and robot defaults

| Selector | Scope | Stored in |
|---|---|---|
| Global default preset | new ordinary sessions | DSH's native `permission` namespace (`defaultPreset`) |
| LLM-robot default preset | social-channel sessions (matched by workspace) | this plugin's `permission-matrix` namespace |

Robot detection is **deliberately decoupled** from any specific bot plugin: it only matches the session workspace (cwd) against `robotWorkspaces`. Uninstalling a bot plugin leaves this plugin working — those workspaces simply stop producing sessions.

## Install

```sh
dsh plugin --profile <profile> add dsh-permission-matrix
```

If `dsh-auto-classifier` is also installed, disable it (both patch the same `permission` row). The patch entry must carry `name`, or `disabled` is ignored:

```yaml
- id: auto-classifier
  name: dsh-auto-classifier
  disabled: true
  config: { enabled: false, presetName: auto }
```

## Configuration

Settings → **Permission Matrix**, or the `permission-matrix` row of `<profile>/cordis.patch.yml`:

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | master switch |
| `takeover` | see above | preset id → tier (`auto-allow` / `classify`) |
| `midRiskPolicy` | `deny` | `deny` / `allow` / `ask` |
| `llmJudge` | `true` | enable the LLM judge |
| `judgeProvider` / `judgeModel` | empty | empty = follow the current session model |
| `judgeStages` | `both` | `both` / `fast` / `thinking` |
| `autoAllowHardGuard` | `true` | hard-deny protection in the auto-approve tier |
| `robotDefaultPreset` | `fa-auto` | default preset for robot sessions |
| `robotWorkspaces` | `[]` | robot session workspaces (absolute paths, subdirs included) |
| `gitSnapshot` | `true` | git checkpoint before granting |
| `gitSnapshotIntervalMs` | `30000` | checkpoint throttle |
| `auditLog` | `true` | audit switch |
| `auditFile` | `~/.dsh/permission-matrix/audit.jsonl` | audit path |

Invalid configuration (unknown preset id, illegal tier) **fails loudly at load time** instead of silently degrading.

## Audit

One JSONL line per decision, written to the audit file and the process log — **never into the model transcript**.

## Architecture

```
src/
├── index.js           assembly + three hooks (tools/pre-execute, approval/request, session/created)
├── presets.js         single source of truth for the 9 presets
├── preset-router.js   current session preset → takeover?
├── decide.js          pure decision core
├── rules.js           hard-deny / allow tables + field projection
├── judge.js           two-stage LLM judge
├── snapshot.js        git checkpoint
├── audit.js           JSONL audit
├── robot-presets.js   robot workspace → default preset
├── settings.js        settings namespace + same-origin web routes
└── client/index.js    settings page (hand-written __ModuleLoader__ bundle)
```

## Test

```sh
node --test tests/decide.test.js tests/hooks.test.js
```

## References and acknowledgements

This plugin's design was informed by three community plugins (ideas borrowed, trade-offs revisited; **the code is an independent implementation**):

### 1. [dsh-auto-classifier](https://github.com/nanmicoder/dsh-auto-classifier) — primary reference

- **Borrowed**: the single `auto` preset concept (low-risk pass / dangerous block / automatic adjudication of sandbox escalations), the `tools/pre-execute` + `approval/request` double hook with `{prepend:true}`, HARD/SOFT risk tiers, the `Tool(pattern)` rule syntax, field projection (command tools scan only `command`/`code`, path tools only `file_path`), in-workspace structural pass, the two-stage LLM judge (fast filter + thinking review), denial logging, and git checkpointing.
- **Improved**: turned the single `auto` preset into **9 composable presets** (3 sandboxes × 4 approval strategies); refined risk tiers from two into **low / medium / high plus hard (fixed deny)**, each of the first three **independently configurable** as allow / deny / escalate; added global-default and LLM-robot-default dimensions.
- **Fixed**: that plugin calls `permissionPresets.current(session.events)` (an old signature) which is silently swallowed by its own `try/catch` on DSH 0.1.2-rc.1; this plugin uses the correct `current(session)` and falls back to reading the projection.

### 2. [dsh-auto-approval-plugin](https://github.com/StyxNether/dsh-auto-approval-plugin) — approval answerer reference

- **Borrowed**: registering an `approval/request` listener that returns `allowed-once` to implement auto-approval, reading the **real tool arguments** from the session log by `callId` (never trusting the model-written justification), resolving paths through `realpath` before deciding area containment, and always deferring on failure.
- **Improved**: this plugin's auto-approve tier keeps a **hard-deny guard** (irreversible/destructive operations are still rejected rather than auto-approved).

### 3. [dsh-yolo-mode](https://github.com/SeverusZh/dsh-yolo-mode) — graded-adjudication reference

- **Borrowed**: using an LLM to adjudicate sandbox **escalation requests**, the `allow / judge / delegate / deny` decision vocabulary, `fail-closed` behaviour (timeout / invalid output / model unavailable all deny or defer), and one JSONL audit line per decision.
- **Improved**: escalation-to-human is a configurable policy on the medium/high tiers, and the "full access has no approval channel" limitation is solved by returning `{kind:'ask'}` from `tools/pre-execute` so the approval seam escalates to a human (see design doc §0.1).

### Other references

- Official DSH docs: `docs/subsystems/approval.zh.md` (approval seam semantics), `docs/cookbook/extension-cookbook.zh.md` (permission-gate example), `docs/cookbook/adding-a-settings-card.zh.md` (the two halves of a settings card).
- The hard-deny rule set merges the default deny / dangerous patterns shipped by the three plugins above.

## License

MIT
