# AI Usage Bar

A native Swift/AppKit **macOS menu-bar + Touch Bar** app that shows how much of your
**Claude Code** and **Codex** rate-limit quota is left — 5-hour and weekly windows, as
segmented "battery" bars with remaining percentage and reset time.

> **Unofficial.** This project is not affiliated with, endorsed by, or supported by
> Anthropic or OpenAI. "Claude" and "Codex" are trademarks of their respective owners.
> It uses **undocumented** local/remote interfaces that may change or break at any time.

## Features

- **Menu bar**: a battery icon + `Claude NN%` (remaining of the 5-hour window).
- **Dropdown menu**: two-row segmented bars (5-hour / weekly) with `NN% 剩余 · 重置 …`.
- **Touch Bar**: both providers side by side — `Claude Code | Codex` — each with its
  own 5-hour and weekly bars.
- Auto-refresh every 60 s; new data only replaces old once a full snapshot arrives.
- Color-coded: green ≥ 50 %, orange ≥ 20 %, red < 20 % remaining.

## How it works

**Claude Code** has no local server, so usage comes from the account usage endpoint:

- Reads the OAuth token from the macOS Keychain item `Claude Code-credentials`
  (the same item Claude Code itself uses).
- Calls `GET https://api.anthropic.com/api/oauth/usage`
  (header `anthropic-beta: oauth-2025-04-20`).
- If the access token is expired, it refreshes via
  `POST https://console.anthropic.com/v1/oauth/token` and **writes the rotated tokens
  back to the same Keychain item** so Claude Code stays in sync.

**Codex** exposes a local app-server, so usage comes from there (no network of our own):

- Spawns `/Applications/Codex.app/Contents/Resources/codex app-server --listen stdio://`.
- Performs JSON-RPC `initialize` → `initialized` → `account/rateLimits/read`.

Remaining quota is computed as `100 - usedPercent`.

## Privacy & security

- The app only talks to **`api.anthropic.com` / `console.anthropic.com`** (Claude) and
  your **local Codex app-server** (Codex). Nothing is sent anywhere else.
- It reads — and on refresh, updates — only the `Claude Code-credentials` Keychain item.
  Tokens never leave your machine and are never written into the repo.
- On first launch macOS will ask to allow Keychain access; click **Always Allow**.
- For troubleshooting it caches the latest usage *response* to
  `~/.claude-usage-debug.json` (usage numbers only — **no tokens**). Delete it any time.

## Requirements

- macOS 13+
- Swift 6 toolchain (Xcode or Command Line Tools)
- Logged-in **Claude Code** and/or **Codex** (`/Applications/Codex.app`) for the
  respective half to populate
- A physical Touch Bar is only present on 2016–2019 Intel MacBook Pros; on other Macs the
  menu-bar UI is the usable surface (the Touch Bar code is included for parity)

## Build & run

Development run:

```bash
swift run
```

Package a `.app` bundle (ad-hoc signed):

```bash
chmod +x scripts/build-app.sh
./scripts/build-app.sh
open "build/AI Usage Bar.app"
```

The app is ad-hoc signed, so the first time you may need to right-click → **Open** to get
past Gatekeeper, and **Always Allow** the Keychain prompt.

## Limitations

- Uses undocumented endpoints; field names/shapes may change. The Claude parser is
  intentionally tolerant and falls back gracefully.
- The token refresh endpoint is aggressively rate-limited per account — the app backs off
  on HTTP 429 and reuses the cached token until it expires.

## Acknowledgements

The Codex side reuses the `codex app-server` JSON-RPC pattern from the companion
Codex Usage Bar project.

## License

[MIT](LICENSE)
