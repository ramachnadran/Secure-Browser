Claude Artifact 

1. What the Browser Blocks (What Native Unlocks)
Everything we hit a wall on is possible natively because a native application has OS-level access that a web page does not have.

Capability

Browser (Web Page)

Native Secure Browser

List all running apps/processes

❌ Impossible

✅ Yes

Kill / block prohibited apps

❌

✅ Yes

Full peripheral list (all USB)

❌ Voluntary only

✅ Yes

External monitor detection + enforcement

⚠️ Detect only (Chrome)

✅ Detect + block

Block Alt-Tab / task switching / shortcuts

❌

✅ Kiosk lockdown

Disable copy/paste / print-screen / screen recording

❌

✅ OS-level

Restrict network to allowed domains

❌

✅

Screenshot/recording detection

❌

✅ OS APIs

Webcam/mic proctoring capture

✅ With permission

✅ Fuller control

2. Can We Build It? Yes — The Model That Fits the Requirement
The requirement is something that runs over the test interface and works for any company's test/interview tool.

That's a Secure Browser shell: a native desktop application that embeds a browser engine and loads the exam URL inside a locked-down window.

Technology
Electron (Chromium + Node.js) — fastest path, cross-platform (Windows + macOS), with a large ecosystem.

CEF can be considered for a lighter footprint.

SEB itself is native + an embedded browser.

Native OS Layer
Native OS modules are required for:

Process enumeration

Display detection

Kiosk lockdown

These can be implemented through Node native addons / OS APIs.

Distribution
Installers need to be:

Signed for Windows using code signing

Notarized for macOS

This is mandatory for distribution and trust.

3. How It Works — Architecture


┌──────────────────────────────────────────────┐
│       Ei Secure Browser (native Electron app)│
│                                              │
│  ┌────────────────────────────────────────┐  │
│  │        Embedded Chromium window        │  │
│  │              (kiosk)                   │  │
│  │                                        │  │
│  │ → loads ANY test/interview URL         │  │
│  │   (your test, competitor, interview)  │  │
│  └────────────────────────────────────────┘  │
│                                              │
│  Native layer (runs alongside, always on):   │
│                                              │
│  • process monitor  → blacklist/allowlist   │
│  • display monitor  → block 2nd screen      │
│  • peripheral scan  → full USB/device list  │
│  • lockdown         → no alt-tab/shortcuts  │
│  • network filter   → allowed domains only  │
│  • webcam/mic       → proctoring capture    │
│  • telemetry        → send alerts to server │
│                                              │
└──────────────────────────────────────────────┘
Launch
The student installs the Secure Browser once and then:

Launches it through a custom protocol link clicked on the web page:



eiproctor://start?exam=…
Or opens the application and enters a test code.

Configuration Per Exam / Order
A signed configuration, similar to SEB's .seb file, or a token can specify:

Allowed URL(s)

Blacklist / allowlist

Security rules

The configuration is fetched at launch.

This is where per-test-type settings live.

Enforcement
The native layer locks down the environment regardless of which page is loaded.

Therefore, the loaded page does not need to know about the security enforcement.

4. Supporting Any Company's Interface + Interview Tools
The Secure Browser shell is URL-agnostic — it simply loads whatever URL is specified by the configuration.

There are two integration levels.

Level 1 — Transparent
Works out of the box without vendor changes.

Kiosk lockdown, process monitoring, display monitoring, and peripheral enforcement apply to any loaded page.

Examples:

Your test

A competitor's test

A web interview tool

Zoom/Meet web client

The vendor does not need to make any changes.

Level 2 — Deep Integration (Optional)
Expose a small JS bridge through an injected preload script.

The loaded page can then query signals such as:



"is a 2nd monitor connected?"
"list of blocked apps"
or trigger events.

Only vendors who adopt the API get this additional integration.

Everyone else continues to use Level 1.

Overall Model
Generic lockdown for everyone; optional richer signals for partners who integrate.

That's how it becomes a platform, not a one-app tool.

5. The Reality — Honest Scope
Product vs Feature
This is a product, not a feature.

Realistically, it would require several months of work and involve:

Cross-platform development

Security-sensitive implementation

Code signing

macOS notarization

QA across multiple OS versions

Ongoing maintenance

Windows/macOS updates may break native hooks, so continuous maintenance will be required.

macOS vs Windows
macOS is harder than Windows.

Apple's sandboxing limits some lockdown capabilities, including the ability to fully block all application switching without special entitlements.

Windows is more permissive.

Build vs Buy Trade-Off
Build In-House
Full control

No per-exam vendor cost

Works with any interface

Big upfront development cost

Ongoing maintenance cost

Adopt / Fork SEB
Open-source

Free

Huge head start

Configure + skin it

Less work than building from scratch

Keep Talview
Zero build effort

Per-use cost

Limited to what their SDK exposes

Existing gaps remain where the SDK does not provide the required capabilities
