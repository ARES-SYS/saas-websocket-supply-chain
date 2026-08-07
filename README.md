# SaaS WebSocket Supply Chain — The Tunnel They Hand You

> **Security Research — August 2026**
>
> 7 platforms. 7 million weekly downloads. One architectural flaw.
> Every SaaS SDK with a WebSocket connection is one compromised npm token away
> from becoming an undetectable C2 tunnel. Here's how to stop it.

---

## The Problem

Your application installs a SaaS SDK — chat, push notifications, real-time sync.
The SDK opens a WebSocket to `*.sendbird.com`, `*.firebaseio.com`, `*.socket.io`.
Your firewall allows it because blocking it breaks production.

Now imagine the npm publish token for that SDK gets compromised.

The attacker adds **one line** to `package.json`:

```json
"scripts": { "preinstall": "node payload.js" }
```

npm runs it **before** integrity verification. Full user privileges. No prompt.

The payload hijacks the existing WebSocket — the one already connected to the
allowlisted SaaS domain — and multiplexes C2 frames through it. Same TLS
handshake. Same certificate. Same RFC 6455 framing. **Zero detection surface
at the network layer.**

The application handed them a tunnel. They didn't even have to ask.

---

## Scale

| # | Platform | npm Package | Weekly Downloads | WSS Endpoint |
|---|---|---|---|---|
| 1 | Sendbird | `sendbird` | 80K+ | `wss://ws.sendbird.com` |
| 2 | Pusher | `pusher-js` | 500K+ | `wss://ws-*.pusher.com` |
| 3 | PubNub | `pubnub` | 100K+ | `wss://*.pubnub.com` |
| 4 | Stream | `stream-chat` | 50K+ | `wss://chat.stream-io-api.com` |
| 5 | Firebase | `@firebase/database` | **1M+** | `wss://*.firebaseio.com` |
| 6 | Socket.io | `socket.io-client` | **5M+** | `wss://*.socket.io` |
| 7 | Azure Web PubSub | `@azure/web-pubsub` | 20K+ | `wss://*.webpubsub.azure.com` |

**Combined: 7,000,000+ weekly downloads.** Every single one shares the same
single point of failure: an npm publish token with no runtime integrity check.

---

## Why the Network Can't See It

| Security Layer | What It Sees | Verdict |
|---|---|---|
| Firewall | `*.firebaseio.com` → ALLOW | Business critical |
| WAF | Valid WebSocket upgrade | Pass |
| DLP | TLS 1.3 encrypted payload | No inspection |
| IDS/IPS | RFC 6455 compliant frames | No signature |
| SOC | "Normal SaaS traffic" | Ignored |

**Detection must happen at the source code.** That's what this tool does.

---

## Detection Tool

```bash
python3 detect.py /path/to/project
```

Scans `node_modules` for compromise indicators across all 7 platforms.

```
⚠  HIGH — 4 findings:
  [magic_bytes_c2]       SDK.min.js:1   — C2 magic byte sequence
  [ws_prototype_hijack]  SDK.min.js:1   — WebSocket prototype hijack
  [preinstall_hook]      package.json:1 — preinstall script in SaaS SDK
  [eval_obfuscated]      SDK.min.js:12  — Obfuscated eval pattern
```

**What it catches:**
- `preinstall` / `postinstall` hooks in SaaS SDK `package.json`
- C2 magic byte sequences embedded in source
- `WebSocket.prototype.send` / `addEventListener` hijacking
- Obfuscated `eval` calls
- Recon commands (`whoami`, `hostname`) — attacker fingerprinting
- Global object pollution for C2 persistence

Zero dependencies. Python 3 stdlib. `--json` for CI/CD, `--summary` for pipelines.

---

## Traffic Simulation

```bash
python3 detect.py --simulate
```

Shows how C2 frames interleave with legitimate application traffic — identical
TLS, identical cert, identical framing. Educational. No network connection made.

---

## Mitigations

### Today

```bash
# 1. Audit every preinstall hook in your dependency tree
find node_modules -name "package.json" -exec grep -l '"preinstall\|postinstall"' {} \;

# 2. Pin versions with integrity hashes
npm ci          # NEVER npm install in CI/CD

# 3. Lock CI/CD publish to commit SHAs, not branch refs
```

### This Sprint

4. Push SaaS vendors to use **separate WSS subdomains** — `chat-ws.sendbird.com` not `ws.sendbird.com`.
5. Monitor WSS traffic patterns — C2 heartbeats don't look like chat messages.
6. Require **npm provenance** and signed attestations for every SaaS SDK.

### Roadmap

7. **Runtime integrity:** SDKs must hash themselves before dialing WebSocket.
8. **Network segmentation:** SaaS traffic through inspected proxy, not direct.
9. **Assume compromise:** Design policy as if any WebSocket could be a tunnel.

---

## Why This Matters

Supply chain attacks are not theoretical. In 2024-2026, npm supply chain
compromises increased by over 300%. The `preinstall` hook is the most
common initial access vector — and it executes before any integrity check.

This repository covers the 7 most widely deployed SaaS SDKs with persistent
WebSocket connections. Combined, they represent over **7 million weekly
downloads** — every single one a potential tunnel. If you run `npm install`
on any project using Firebase (1M+/wk) or Socket.io (5M+/wk), you are
one compromised publish token away from an undetectable C2 channel.

The industry treats these packages as trusted because they come from major
vendors. But trust is not verification. Run the scanner. Verify your stack.
Assume compromise.

---

## Files

| File | Description |
|---|---|
| `detect.py` | Multi-platform compromise scanner + traffic simulation |
| `README.md` | This document |
| `LICENSE` | MIT |

## License

MIT.

---

> *"They don't need to break encryption. The application hands them a tunnel."*
