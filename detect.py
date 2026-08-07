#!/usr/bin/env python3
"""
Multi-Platform SaaS WebSocket Supply Chain — Defensive Detection Tool

Scans node_modules for compromise indicators across 7 SaaS platforms:
Sendbird, Pusher, PubNub, Stream, Firebase, Socket.io, Azure Web PubSub.

Detects pre-npm-v12 (preinstall hooks) AND post-npm-v12 (binding.gyp node-gyp
abuse, install-time execution vectors) supply chain compromise patterns.

USAGE:
  python3 detect.py /path/to/project     Scan for compromise
  python3 detect.py --simulate           Show how C2 blends into WSS traffic
  python3 detect.py . --fix              Remove preinstall hooks from node_modules
  python3 detect.py . --json             JSON output for CI/CD pipelines
  python3 detect.py --help               Full options

Security research — August 2026
"""
import argparse, base64, json, os, re, sys, textwrap

# WSS endpoints across 7 SaaS platforms
SAAS_ENDPOINTS = {
    "Sendbird":          "wss://ws.sendbird.com",
    "Pusher":            "wss://ws-*.pusher.com",
    "PubNub":            "wss://*.pubnub.com",
    "Stream":            "wss://chat.stream-io-api.com",
    "Firebase":          "wss://*.firebaseio.com",
    "Socket.io":         "wss://*.socket.io",
    "Azure Web PubSub":  "wss://*.webpubsub.azure.com",
}

# ═══════════════════════════════════════════════════════════
# DETECTION INDICATORS
# ═══════════════════════════════════════════════════════════

INDICATORS = [
    # (name, regex, description, severity)
    ("preinstall_hook",
     r'"preinstall"\s*:',
     "npm preinstall script — executes at install time with full privileges",
     "HIGH"),

    ("postinstall_hook",
     r'"postinstall"\s*:',
     "npm postinstall script — executes after install",
     "HIGH"),

    # ── Post-npm-v12 vectors ─────────────────────────────

    ("binding_gyp",
     r"binding\.gyp",
     "binding.gyp file present — node-gyp executes code during npm install without preinstall hook. Used by Miasma worm (2026).",
     "HIGH"),

    ("gyp_command_substitution",
     r"<\s*!\s*@\s*\(\s*.*?\|\|.*?\)\s*>",
     "node-gyp command substitution in .gyp file — arbitrary code execution at npm install (Miasma technique).",
     "HIGH"),

    ("gyp_shell_exec",
     r'"variables"\s*:\s*\{[^}]*"command"\s*:',
     "node-gyp variable with 'command' key — may execute shell commands during build.",
     "MEDIUM"),

    ("base64_payload",
     r'(?:["\'])((?:[A-Za-z0-9+/]{40,}={0,2})|(?:[A-Za-z0-9+/]{60,}={0,2}))(?:["\'])',
     "Long base64 string — may contain encoded payload (verify manually)",
     "MEDIUM"),

    ("magic_bytes_c2",
     r"(?:0xAA\s*,\s*0xBB\s*,\s*0xCC\s*,\s*0xDD|AABBCCDD|\\xAA\\xBB\\xCC\\xDD)",
     "C2 magic byte sequence — used to differentiate C2 frames from app data",
     "HIGH"),

    ("ws_prototype_hijack",
     r"WebSocket\.prototype\.(?:send|addEventListener|onmessage)\s*=",
     "WebSocket prototype hijack — intercepting all WSS frames",
     "HIGH"),

    ("ws_prototype_override",
     r"WebSocket\.prototype\.\w+\s*=\s*function",
     "WebSocket method override — possible C2 frame routing",
     "MEDIUM"),

    ("eval_obfuscated",
     r"eval\s*\(\s*[a-zA-Z_$]{1,4}\(",
     "Obfuscated eval — common in injected C2 payloads",
     "MEDIUM"),

    ("global_persistence",
     r"global\.__[a-z_]+\s*=",
     "Global object pollution — C2 API persistence mechanism",
     "MEDIUM"),

    ("child_process_injection",
     r"(?:execSync|spawn|exec)\s*\(\s*['\"]whoami|hostname|id['\"]",
     "Recon command in injected code — attacker fingerprinting the host",
     "MEDIUM"),

    ("wss_endpoint",
     r"wss://(?:ws|api|tsock|global\.vss|ws-|chat)\.(?:sendbird|pusher|pubnub|stream-io-api|firebaseio|socket\.io|webpubsub\.azure)\.(?:com|io|net)",
     "SaaS WebSocket endpoint (expected — verify it belongs to the SDK)",
     "INFO"),
]

# SDK packages known to use WSS endpoints legitimately
KNOWN_SDK_DIRS = {
    "sendbird", "pusher-js", "pusher", "pubnub", "stream-chat",
    "@firebase", "firebase", "socket.io-client", "socket.io",
    "@azure/web-pubsub", "azure-web-pubsub",
}

SKIP_DIRS = {".git", "__pycache__", ".cache", ".bin", "dist", "build"}


# ═══════════════════════════════════════════════════════════
# .scanignore
# ═══════════════════════════════════════════════════════════

def load_scanignore(scan_path: str) -> set[str]:
    """Load .scanignore patterns from the project root."""
    ignore = set()
    ignorefile = os.path.join(scan_path, ".scanignore")
    if os.path.isfile(ignorefile):
        try:
            with open(ignorefile, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        ignore.add(line)
        except OSError:
            pass
    return ignore


def is_ignored(filepath: str, root: str, patterns: set[str]) -> bool:
    """Check if a file matches any .scanignore pattern."""
    rel = os.path.relpath(filepath, root)
    for pat in patterns:
        # Simple substring match (supports dir/ and .ext patterns)
        if pat.endswith("/") and rel.startswith(pat):
            return True
        if pat.startswith("*.") and rel.endswith(pat[1:]):
            return True
        if pat in rel:
            return True
    return False


# ═══════════════════════════════════════════════════════════
# SCANNERS
# ═══════════════════════════════════════════════════════════

def scan_file(filepath: str) -> list[dict]:
    """Scan a single file and return any findings."""
    findings = []
    try:
        with open(filepath, "r", errors="ignore") as f:
            content = f.read()
    except (OSError, PermissionError):
        return findings

    for name, pattern, desc, severity in INDICATORS:
        for m in re.finditer(pattern, content, re.IGNORECASE):
            line_no = content[:m.start()].count("\n") + 1

            # Base64: skip if it's just a version hash or known-safe
            if name == "base64_payload":
                b64 = m.group(1)
                if not _is_suspicious_base64(b64):
                    continue

            start = max(0, m.start() - 30)
            end = min(len(content), m.end() + 30)
            snippet = content[start:end].replace("\n", "\\n").strip()
            findings.append({
                "file": filepath,
                "line": line_no,
                "indicator": name,
                "description": desc,
                "severity": severity,
                "snippet": snippet[:90],
            })
    return findings


def _is_suspicious_base64(b64: str) -> bool:
    """Filter out common non-malicious base64 strings."""
    # Skip strings that look like npm integrity hashes (sha512-...)
    if b64.startswith("sha") or b64.startswith("md5"):
        return False
    # Try to decode — if it's valid base64 and contains shell-like patterns
    try:
        decoded = base64.b64decode(b64, validate=True).decode("utf-8", errors="ignore")
        suspicious = any(kw in decoded.lower() for kw in
                         ["http", "curl", "wget", "eval", "exec", "child_process",
                          "whoami", "hostname", "/bin/", "require(", "websocket"])
        return suspicious
    except Exception:
        return False


def scan_project(scan_path: str, ignore_patterns: set[str] | None = None) -> tuple[list[dict], int]:
    """Walk a directory and scan all JS/TS/JSON files.
    Returns (findings, files_scanned).
    """
    if not os.path.isdir(scan_path):
        print(f"ERROR: {scan_path} is not a directory", file=sys.stderr)
        return [], 0

    if ignore_patterns is None:
        ignore_patterns = load_scanignore(scan_path)

    all_findings = []
    files_scanned = 0

    for root, dirs, files in os.walk(scan_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for fname in files:
            if not fname.endswith((".js", ".json", ".ts", ".mjs", ".cjs", ".gyp", ".gypi")):
                continue
            fpath = os.path.join(root, fname)
            if is_ignored(fpath, scan_path, ignore_patterns):
                continue
            findings = scan_file(fpath)
            all_findings.extend(findings)
            files_scanned += 1

    # Also scan root package.json if present
    root_pkg = os.path.join(scan_path, "package.json")
    if os.path.isfile(root_pkg) and not is_ignored(root_pkg, scan_path, ignore_patterns):
        findings = scan_file(root_pkg)
        all_findings.extend(findings)
        files_scanned += 1

    return all_findings, files_scanned


# ═══════════════════════════════════════════════════════════
# AUTO-FIX
# ═══════════════════════════════════════════════════════════

def fix_preinstall_hooks(scan_path: str, findings: list[dict], dry_run: bool = False) -> int:
    """Remove preinstall/postinstall hooks from package.json files.
    Returns number of files modified.
    """
    fixed = 0
    # Group by file, only fix preinstall/postinstall findings
    hook_findings = [f for f in findings
                     if f["indicator"] in ("preinstall_hook", "postinstall_hook")]

    files_to_fix = set(f["file"] for f in hook_findings)

    for filepath in sorted(files_to_fix):
        if not filepath.endswith("package.json"):
            continue
        try:
            with open(filepath, "r") as f:
                content = f.read()

            # Remove preinstall and postinstall from scripts
            cleaned = re.sub(
                r',?\s*"(?:pre|post)install"\s*:\s*"[^"]*"',
                '',
                content
            )
            # Clean up double commas left behind
            cleaned = re.sub(r',\s*,', ',', cleaned)
            cleaned = re.sub(r'\{\s*,', '{', cleaned)
            cleaned = re.sub(r',\s*\}', '}', cleaned)

            if cleaned != content:
                if dry_run:
                    print(f"  [DRY RUN] Would fix: {filepath}")
                else:
                    with open(filepath, "w") as f:
                        f.write(cleaned)
                    print(f"  ✓ Fixed: {filepath}")
                fixed += 1
        except (OSError, PermissionError) as e:
            print(f"  ✗ Error: {filepath} — {e}", file=sys.stderr)

    return fixed


# ═══════════════════════════════════════════════════════════
# TRAFFIC SIMULATION (PURELY EDUCATIONAL)
# ═══════════════════════════════════════════════════════════

def simulate_traffic():
    """Show how C2 frames are indistinguishable from legitimate WSS."""

    legit_examples = [
        ("TEXT", 72, '{"type":"message","channel":"support","text":"Hi"}'),
        ("TEXT", 60, '{"type":"typing","channel":"support","user":"agent"}'),
        ("TEXT", 67, '{"type":"message","channel":"general","text":"OK"}'),
        ("TEXT", 57, '{"type":"presence","user":"alice","status":"online"}'),
    ]

    c2_examples = [
        ("BIN", 48, '[MAGIC] {"c2":true,"cmd":"exfil","id":"0x01"}'),
        ("BIN", 52, '[MAGIC] {"c2":true,"cmd":"heartbeat"}'),
        ("BIN", 77, '[MAGIC] {"c2":true,"cmd":"exec","args":"whoami"}'),
        ("BIN", 48, '[MAGIC] {"c2":true,"cmd":"exfil","id":"0x02"}'),
    ]

    print("=" * 60)
    print("  WebSocket SaaS C2 — Traffic Simulation (Educational)")
    print("=" * 60)
    print()
    print("Target: wss://<saas-platform>.com (TLS 1.3, valid SaaS cert)")
    print("Applies to: Sendbird, Pusher, PubNub, Stream, Firebase, Socket.io, Azure")
    print()
    print("Frame flow — legitimate app frames interleaved with C2:")
    print("-" * 60)
    print(f"  {'#':>2}  {'Type':>6}  {'Size':>5}  Content")
    print("-" * 60)

    for i in range(8):
        if i % 2 == 0:
            ftype, size, content = legit_examples[i // 2]
            tag = "APP"
        else:
            ftype, size, content = c2_examples[i // 2]
            tag = "C2"

        print(f"  {i+1:>2}  [{tag:>5}]  {size:>4}B  {content[:55]}")

    print("-" * 60)
    print()
    print("Network-layer view:")
    print("  Source IP:   SaaS CDN (legitimate infrastructure)")
    print("  Protocol:    WSS over TLS 1.3")
    print("  Certificate: *.saas-platform.com (valid, trusted CA)")
    print("  Frames:      RFC 6455 compliant (binary + text)")
    print()
    print("Detection surface at network layer: NONE")
    print()
    print("Why:")
    print("  - Firewall sees:  *.saas-platform.com → ALLOW (business critical)")
    print("  - WAF sees:       valid WebSocket upgrade + valid frames")
    print("  - DLP sees:       encrypted payload, no inspection possible")
    print("  - IDS/IPS sees:   no known signature, no protocol anomaly")
    print("  - SOC sees:       'normal SaaS traffic'")
    print()
    print("CONCLUSION: Detection must happen at the SOURCE CODE level.")
    print("Run: python3 detect.py /path/to/project")
    print()


# ═══════════════════════════════════════════════════════════
# REPORT FORMATTING
# ═══════════════════════════════════════════════════════════

def print_report(findings: list[dict], files_scanned: int, scan_path: str):
    """Print a human-readable detection report."""

    print("=" * 60)
    print("  Supply Chain Compromise Scan")
    print("=" * 60)
    print(f"  Path:          {scan_path}")
    print(f"  Files scanned: {files_scanned}")
    print(f"  Findings:      {len(findings)}")
    print()

    if not findings:
        print("  ✓  No compromise indicators found.")
        print()
        print("  Recommendations:")
        print("    1. Run on a project with node_modules: detect.py ./project")
        print("    2. Add to CI/CD: detect.py . --json")
        print("    3. Pair with: npm audit, npm audit signatures")
        return

    by_severity = {"HIGH": [], "MEDIUM": [], "INFO": []}
    for f in findings:
        by_severity[f["severity"]].append(f)

    for sev in ["HIGH", "MEDIUM", "INFO"]:
        items = by_severity[sev]
        if not items:
            continue

        icon = {"HIGH": "⚠", "MEDIUM": "●", "INFO": "ℹ"}[sev]
        print(f"  {icon}  {sev} severity — {len(items)} finding(s)")
        print(f"  {'─' * 50}")

        for item in items:
            print(f"  [{item['indicator']}] {item['file']}:{item['line']}")
            print(f"    {item['description']}")
            print(f"    → {item['snippet']}")
            print()

    print("-" * 60)
    print("  NEXT STEPS (if HIGH findings):")
    print("  1. Isolate the affected system from the network")
    print("  2. Check npm registry — is the installed version legitimate?")
    print("  3. Diff package.json against the published tarball")
    print("  4. Verify npm publish provenance (npm audit signatures)")
    print("  5. Rotate credentials exposed on the affected host")
    print("  6. Run: python3 detect.py . --fix (removes preinstall hooks)")
    print()


# ═══════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Multi-Platform SaaS WebSocket Supply Chain — Defensive Detection Tool",
        epilog="Security research — August 2026"
    )
    parser.add_argument(
        "path", nargs="?", default=None,
        help="Path to scan (project root or node_modules directory)"
    )
    parser.add_argument(
        "--simulate", action="store_true",
        help="Run educational traffic simulation"
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output findings as JSON (for CI/CD pipelines)"
    )
    parser.add_argument(
        "--summary", action="store_true",
        help="Summary only (no per-file details)"
    )
    parser.add_argument(
        "--fix", action="store_true",
        help="Remove preinstall/postinstall hooks from node_modules package.json"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what --fix would do without changing files"
    )
    args = parser.parse_args()

    if args.simulate:
        simulate_traffic()
        return

    if not args.path:
        parser.print_help()
        print("\nExamples:")
        print("  python3 detect.py ./my-project")
        print("  python3 detect.py --simulate")
        print("  python3 detect.py ./my-project --json")
        print("  python3 detect.py ./my-project --fix")
        sys.exit(1)

    scan_path = os.path.abspath(args.path)
    ignore_patterns = load_scanignore(scan_path)
    findings, files_scanned = scan_project(scan_path, ignore_patterns)

    # --fix / --dry-run
    if args.fix or args.dry_run:
        print("=" * 60)
        print("  Auto-Fix: Preinstall/Postinstall Hook Removal")
        print("=" * 60)
        print(f"  Path:     {scan_path}")
        print(f"  Mode:     {'DRY RUN (no changes)' if args.dry_run else 'LIVE'}")
        print()
        fixed = fix_preinstall_hooks(scan_path, findings, dry_run=args.dry_run)
        print()
        print(f"  Files {'would be ' if args.dry_run else ''}modified: {fixed}")
        print()
        if not args.dry_run and fixed > 0:
            # Re-scan after fix
            print("  Re-scanning after fix...")
            findings, files_scanned = scan_project(scan_path, ignore_patterns)
        elif not args.dry_run and fixed == 0:
            print("  No preinstall/postinstall hooks found to fix.")

    if args.json:
        output = {
            "path": scan_path,
            "files_scanned": files_scanned,
            "findings_count": len(findings),
            "findings": findings,
        }
        print(json.dumps(output, indent=2))
        sys.exit(1 if any(f["severity"] == "HIGH" for f in findings) else 0)

    if args.summary:
        high = sum(1 for f in findings if f["severity"] == "HIGH")
        med = sum(1 for f in findings if f["severity"] == "MEDIUM")
        info = sum(1 for f in findings if f["severity"] == "INFO")
        print(f"Files: {files_scanned} | HIGH: {high} | MEDIUM: {med} | INFO: {info}")
        sys.exit(1 if high > 0 else 0)

    print_report(findings, files_scanned, scan_path)
    sys.exit(1 if any(f["severity"] == "HIGH" for f in findings) else 0)


if __name__ == "__main__":
    main()
