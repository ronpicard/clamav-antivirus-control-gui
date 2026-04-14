# macOS Endpoint Security (preventative scanning) — reference

This folder is **not** a turnkey feature inside ClamAV Control. It documents how **real** “block before open” monitoring works on macOS and provides a **code sketch** you can merge into your own System Extension target.

## Why this app does not ship ES today

- **Endpoint Security clients** run in a **System Extension** (or equivalent privileged target), not inside Electron or Node.
- Apple grants **`com.apple.developer.endpoint-security.client`** only through the Developer Program and their review process for security tools.
- **Authorization events** (e.g. `AUTH_OPEN`) expect a **timely** allow/deny. Running **`clamscan` synchronously** on every open will stall apps and can exceed practical ES deadlines; production AV uses caching, async policies, kernel cooperation, and often **clamd** with careful timeouts—not a trivial bolt-on.

## What you would build

1. **Xcode**: macOS app + **System Extension** target using the **EndpointSecurity** framework.
2. **Entitlements**: endpoint-security client (+ whatever Apple requires for your product class).
3. **Distribution**: signing, notarization, user approval of the system extension in **System Settings**.
4. **Scan path**: extension receives `AUTH_*` messages → decide allow/deny (or defer with care per Apple docs) → optionally **XPC** or **Unix domain socket** to a helper that talks to **clamd** / runs **clamdscan** with strict policy.
5. **UI integration** (optional): this Electron app could later **discover** or **configure** the helper (paths, enable/disable) via a local socket or `launchd`—the extension itself cannot be “just npm installed.”

## Apple starting points

- [Endpoint Security](https://developer.apple.com/documentation/endpointsecurity)
- System Extensions / `OSSystemExtensionRequest` for loading your extension
- Sample projects in Apple’s developer libraries (search for Endpoint Security sample code)

## Files here

- `Reference/ESClientSketch.swift` — illustrative handler shape for `AUTH_OPEN`. **Paste into** a System Extension target that already has the entitlement; it will not compile as a standalone Swift package in this repo.
