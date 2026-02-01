# 🌐 whois — Fast Go CLI for WHOIS lookups

A lightweight Go CLI that fetches WHOIS records for domains from the terminal, optimized for quick, scriptable lookups.

## Installation (Homebrew)
```bash
brew tap bilalbaraz/tap
brew install bilalbaraz/tap/whois
```

## Usage
```bash
whois lookup <domain> [flags]
```

## Flags
- `--raw`     Prints only the raw WHOIS response (no server header).
- `--json`    Prints the response as JSON (parsed fields; falls back to raw when parsing fails).
- `--server`  Manually set the WHOIS server (host only). Overrides automatic referral lookup.

## Configuration
No config file. All behavior is controlled via CLI flags.

## Notes
- Errors are printed to stderr and exit with code 1 on invalid input.
