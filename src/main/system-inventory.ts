/**
 * System inventory — what the browser can see about the machine it runs on.
 *
 * A web page cannot enumerate running applications or USB peripherals: that is
 * an OS security boundary, not a missing browser feature. This app is native
 * (Electron main process), so it CAN, using only permission-free OS tooling —
 * no TCC prompt, no helper daemon, no admin rights.
 *
 *   apps        macOS `lsappinfo list` / Windows `Get-Process`
 *   peripherals macOS `system_profiler` + `ioreg` / Windows `Get-PnpDevice`
 *   capture     `defaults` + our own content-protection state
 *
 * Everything here is read-only; nothing is killed or unplugged. The snapshot is
 * evidence for the invigilator, and the caller decides what to do about it.
 */
import { execFileSync } from 'child_process';
import * as os from 'os';
import * as path from 'path';

export type AppKind = 'foreground' | 'agent' | 'background';

export interface RunningApp {
  name: string;
  pid: number | null;
  bundleId: string | null;
  kind: AppKind;
  prohibited: boolean;
  /** Which configured rule matched, so the report can explain itself. */
  matchedRule: string | null;
}

export type DeviceCategory =
  | 'usb' | 'bluetooth' | 'input' | 'display' | 'camera' | 'audio';

export interface Peripheral {
  category: DeviceCategory;
  name: string;
  detail: string;
  /** false for built-in hardware (internal keyboard, laptop screen, ...). */
  external: boolean;
  /** Worth an invigilator's attention — see `reason`. */
  flagged: boolean;
  reason: string | null;
}

export interface CaptureStatus {
  /** Our window is excluded from capture (screenshots of it come out blank). */
  contentProtection: boolean;
  /** System-wide screenshot capture is switched off. */
  screenshotsBlocked: boolean;
  /** Where the OS would write a screenshot if one were taken. */
  screenshotDir: string;
  /** macOS TCC status for THIS app recording the screen: granted/denied/... */
  screenRecordingPermission: string;
  /** Known recording / conferencing apps found running right now. */
  recordersRunning: string[];
  /** Virtual camera drivers (OBS, ManyCam, ...) present on the machine. */
  virtualCameras: string[];
}

export interface InventoryCounts {
  foregroundApps: number;
  menuBarAgents: number;
  backgroundDaemons: number;
  totalProcesses: number;
  prohibitedApps: number;
  externalDevices: number;
  flaggedDevices: number;
}

export interface InventorySnapshot {
  at: number;
  reason: string;
  host: string;
  user: string;
  platform: string;
  osRelease: string;
  arch: string;
  counts: InventoryCounts;
  apps: RunningApp[];
  peripherals: Peripheral[];
  capture: CaptureStatus;
  /** Human-readable problems, in the order an invigilator should read them. */
  findings: string[];
  /** No findings at all — safe to start the exam. */
  clean: boolean;
}

export interface InventoryOptions {
  /** Case-insensitive substrings matched against app name and bundle id. */
  prohibitedProcesses: string[];
  /** Content-protection state, which only the window owner knows. */
  contentProtection: boolean;
  /** macOS screen-recording permission for this app, from Electron. */
  screenRecordingPermission: string;
}

/** Run a command and return stdout, or '' if it fails for any reason. */
function sh(cmd: string, args: string[], timeoutMs = 15000): string {
  try {
    return execFileSync(cmd, args, {
      encoding: 'utf-8',
      timeout: timeoutMs,
      maxBuffer: 64 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'ignore']
    });
  } catch {
    return '';
  }
}

/** One `system_profiler` call for every data type we need — it is the slow part. */
function systemProfiler(dataTypes: string[]): Record<string, any[]> {
  const raw = sh('system_profiler', ['-json', ...dataTypes]);
  try {
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

// ---------------------------------------------------------------- applications

/**
 * `lsappinfo` classifies every launched app for us and needs no permission:
 *   Foreground      a real window the student is looking at
 *   UIElement       menu-bar / accessory agent (still visible, still scriptable)
 *   BackgroundOnly  daemon with no UI
 */
function macApps(): RunningApp[] {
  const out: RunningApp[] = [];
  let current: RunningApp | null = null;

  for (const line of sh('lsappinfo', ['list']).split('\n')) {
    const header = line.match(/^\s*\d+\)\s+"(.+?)"/);
    if (header) {
      if (current) out.push(current);
      current = {
        name: header[1],
        pid: null,
        bundleId: null,
        kind: 'agent',
        prohibited: false,
        matchedRule: null
      };
      continue;
    }
    if (!current) continue;

    const bundle = line.match(/bundleID="([^"]+)"/);
    if (bundle) current.bundleId = bundle[1];

    const pid = line.match(/\bpid\s*=\s*(\d+)/);
    if (pid) current.pid = Number(pid[1]);

    const kind = line.match(/type="([^"]+)"/);
    if (kind) {
      current.kind =
        kind[1] === 'Foreground' ? 'foreground'
        : kind[1] === 'BackgroundOnly' ? 'background'
        : 'agent';
    }
  }
  if (current) out.push(current);
  return out;
}

/** Windows equivalent: a window title is the closest thing to "foreground". */
function windowsApps(): RunningApp[] {
  const raw = sh('powershell', [
    '-NoProfile', '-NonInteractive', '-Command',
    'Get-Process | Select-Object Id,ProcessName,MainWindowTitle | ConvertTo-Json -Compress'
  ]);
  let rows: any[];
  try {
    const parsed = JSON.parse(raw);
    rows = Array.isArray(parsed) ? parsed : [parsed];
  } catch {
    return [];
  }
  return rows.filter(Boolean).map(r => ({
    name: String(r.ProcessName ?? 'unknown'),
    pid: typeof r.Id === 'number' ? r.Id : null,
    bundleId: null,
    kind: (r.MainWindowTitle ? 'foreground' : 'background') as AppKind,
    prohibited: false,
    matchedRule: null
  }));
}

function totalProcessCount(fallback: number): number {
  if (process.platform === 'darwin') {
    const lines = sh('ps', ['-axo', 'pid=']).split('\n').filter(l => l.trim());
    if (lines.length) return lines.length;
  }
  return fallback;
}

/**
 * Match a rule as a whole word, not a bare substring. Plain `includes` turns
 * the rule "utm" into a hit on macOS's own TextInputMenuAgent, which is how a
 * blocklist ends up failing honest students. Boundaries are alphanumeric only,
 * so "zoom.us" and "com.obsproject.obs" still match on the punctuation.
 */
function matchesRule(haystack: string, rule: string): boolean {
  const escaped = rule.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(?<![a-z0-9])${escaped}(?![a-z0-9])`, 'i').test(haystack);
}

function markProhibited(apps: RunningApp[], rules: string[]): void {
  const needles = rules.map(r => r.trim().toLowerCase()).filter(Boolean);
  for (const app of apps) {
    const haystack = `${app.name} ${app.bundleId ?? ''}`;
    const hit = needles.find(n => matchesRule(haystack, n));
    if (hit) {
      app.prohibited = true;
      app.matchedRule = hit;
    }
  }
}

// ----------------------------------------------------------------- peripherals

/** Device names that mean "possible second input path or exfiltration route". */
const DEVICE_FLAGS: Array<{ pattern: RegExp; reason: string }> = [
  { pattern: /keyboard|keypad/i,               reason: 'external keyboard — second input path' },
  { pattern: /storage|flash|disk|ssd|sd card|card reader/i, reason: 'mass storage — can carry notes in or answers out' },
  { pattern: /capture|hdmi|video ?grab|elgato/i, reason: 'video capture device — screen can be recorded off-machine' },
  { pattern: /iphone|ipad|android|phone|mobile/i, reason: 'phone or tablet tethered to the exam machine' },
  { pattern: /ethernet|wi-?fi adapter|modem/i,  reason: 'extra network interface' },
  { pattern: /headset|earbud|airpod|earphone/i, reason: 'audio device — audio help cannot be seen on camera' }
];

function flagDevice(name: string): string | null {
  return DEVICE_FLAGS.find(f => f.pattern.test(name))?.reason ?? null;
}

/** USB is a tree of hubs; only the leaves are devices a student plugged in. */
function collectUsb(items: any[], out: Peripheral[]): void {
  for (const item of items ?? []) {
    const children = item._items ?? [];
    const name = String(item._name ?? 'Unknown USB device');
    const isBus = /bus$/i.test(name) || !!item.host_controller;
    const isHub = /hub/i.test(name);

    if (!isBus && !isHub) {
      const vendor = String(item.manufacturer ?? '').trim();
      const speed = String(item.device_speed ?? '').replace(/^speed_/, '');
      const reason = flagDevice(name);
      out.push({
        category: 'usb',
        name,
        detail: [vendor, speed].filter(Boolean).join(' · ') || 'USB device',
        external: true,
        flagged: reason !== null,
        reason
      });
    }
    collectUsb(children, out);
  }
}

/**
 * HID is where a second keyboard actually shows up, including one behind a
 * wireless dongle that presents itself as a single composite USB device.
 * Usage page 1 / usage 6 is the HID spec's "generic desktop keyboard".
 */
function macHidDevices(): Peripheral[] {
  const out: Peripheral[] = [];
  const blocks = sh('ioreg', ['-c', 'IOHIDDevice', '-r', '-d', '1']).split(/^\+-o /m);

  for (const block of blocks.slice(1)) {
    const value = (key: string) =>
      block.match(new RegExp(`"${key}"\\s*=\\s*"?([^"\\n]+)"?`))?.[1]?.trim() ?? '';

    const usagePage = Number(value('PrimaryUsagePage'));
    const usage = Number(value('PrimaryUsage'));
    if (usagePage !== 1 || usage !== 6) continue; // keyboards only

    const transport = value('Transport');
    const product = value('Product') || 'Unnamed keyboard';
    // SPU / FIFO are the Apple-internal buses on Apple silicon laptops.
    const external = !/^(spu|fifo)$/i.test(transport);

    if (out.some(d => d.name === product)) continue; // one entry per keyboard
    out.push({
      category: 'input',
      name: product,
      detail: `keyboard over ${transport || 'unknown bus'}`,
      external,
      flagged: external,
      reason: external ? 'external keyboard — second input path' : null
    });
  }
  return out;
}

function macPeripherals(): Peripheral[] {
  const out: Peripheral[] = [];
  const profile = systemProfiler([
    'SPUSBDataType', 'SPDisplaysDataType', 'SPCameraDataType', 'SPBluetoothDataType'
  ]);

  collectUsb(profile.SPUSBDataType ?? [], out);
  out.push(...macHidDevices());

  for (const gpu of profile.SPDisplaysDataType ?? []) {
    for (const screen of gpu.spdisplays_ndrvs ?? []) {
      const name = String(screen._name ?? 'Display');
      const internal = String(screen.spdisplays_connection_type ?? '').includes('internal');
      const mirrored = String(screen.spdisplays_mirror ?? '').includes('_on');
      out.push({
        category: 'display',
        name,
        detail: String(screen._spdisplays_resolution ?? '').trim() || 'unknown resolution',
        external: !internal,
        flagged: !internal,
        reason: !internal
          ? (mirrored
              ? 'mirrored external display — the exam is visible on a second screen'
              : 'second display — content can be moved off the protected window')
          : null
      });
    }
  }

  for (const cam of profile.SPCameraDataType ?? []) {
    const name = String(cam._name ?? 'Camera');
    const virtual = /virtual|obs|manycam|snap|droidcam|epoccam/i.test(name);
    out.push({
      category: 'camera',
      name,
      detail: String(cam['spcamera_model-id'] ?? 'camera'),
      external: virtual || !/facetime|built-?in/i.test(name),
      flagged: virtual,
      reason: virtual ? 'virtual camera — the proctoring feed can be faked' : null
    });
  }

  for (const controller of profile.SPBluetoothDataType ?? []) {
    for (const entry of controller.device_connected ?? []) {
      for (const [name, info] of Object.entries<any>(entry)) {
        const reason = flagDevice(name);
        out.push({
          category: 'bluetooth',
          name,
          detail: String(info?.device_minorType ?? info?.device_majorType ?? 'paired and connected'),
          external: true,
          flagged: reason !== null,
          reason
        });
      }
    }
  }
  return out;
}

function windowsPeripherals(): Peripheral[] {
  const raw = sh('powershell', [
    '-NoProfile', '-NonInteractive', '-Command',
    "Get-PnpDevice -PresentOnly -Status OK | Where-Object { $_.Class -in " +
    "'USB','Keyboard','Mouse','DiskDrive','Camera','Image','Monitor','Bluetooth','Media' } | " +
    'Select-Object FriendlyName,Class,InstanceId | ConvertTo-Json -Compress'
  ]);
  let rows: any[];
  try {
    const parsed = JSON.parse(raw);
    rows = Array.isArray(parsed) ? parsed : [parsed];
  } catch {
    return [];
  }

  const categoryOf = (cls: string): DeviceCategory =>
    cls === 'Monitor' ? 'display'
    : cls === 'Camera' || cls === 'Image' ? 'camera'
    : cls === 'Bluetooth' ? 'bluetooth'
    : cls === 'Keyboard' || cls === 'Mouse' ? 'input'
    : cls === 'Media' ? 'audio'
    : 'usb';

  return rows.filter(Boolean).map(r => {
    const name = String(r.FriendlyName ?? 'Unknown device');
    const reason = flagDevice(name);
    // A PCI/ACPI instance id is soldered-in hardware, not something plugged in.
    const external = !/^(ACPI|PCI|ROOT)\\/i.test(String(r.InstanceId ?? ''));
    return {
      category: categoryOf(String(r.Class ?? '')),
      name,
      detail: String(r.Class ?? 'device'),
      external,
      flagged: reason !== null && external,
      reason: external ? reason : null
    };
  });
}

// -------------------------------------------------------------- screen capture

/** Recording / conferencing apps that put the exam on someone else's screen. */
export const RECORDER_PROCESSES = [
  'obs', 'QuickTime Player', 'zoom.us', 'screencaptureui', 'Loom', 'Camtasia',
  'ScreenFlow', 'Snagit', 'Screenpal', 'Microsoft Teams', 'AnyDesk',
  'TeamViewer', 'RustDesk', 'Chrome Remote Desktop', 'Screen Sharing', 'vnc'
];

/** Where macOS writes screenshots (user-configurable; defaults to ~/Desktop). */
export function screenshotDir(): string {
  const loc = sh('defaults', ['read', 'com.apple.screencapture', 'location'], 5000).trim();
  if (loc) return loc.replace(/^~/, os.homedir());
  return path.join(os.homedir(), 'Desktop');
}

/** True when system-wide screenshot capture has been switched off. */
export function screenshotsBlocked(): boolean {
  if (process.platform !== 'darwin') return false;
  return sh('defaults', ['read', 'com.apple.screencapture', 'disabled'], 5000).trim() === '1';
}

export function runningRecorders(): string[] {
  const ps = process.platform === 'darwin'
    ? sh('ps', ['-axo', 'comm='])
    : sh('tasklist', ['/fo', 'csv', '/nh']);
  if (!ps) return [];

  const hits = new Set<string>();
  for (const line of ps.split('\n')) {
    const proc = line.trim();
    if (!proc) continue;
    // Apple's own daemons live here and are not something a student launched;
    // ScreenSharingSubscriber.xpc ships with macOS and is always running.
    if (proc.startsWith('/System/') || proc.startsWith('/usr/libexec/')) continue;
    // Auto-updaters ship inside the recorder's own bundle and run whether or
    // not the app is open, so "ZoomUpdater" is not evidence of a Zoom call.
    if (/\/Launch(Agents|Daemons)\//.test(proc)) continue;
    if (/(updater|autoupdate|update helper)$/i.test(proc)) continue;
    for (const name of RECORDER_PROCESSES) {
      if (matchesRule(proc, name)) hits.add(name);
    }
  }
  return [...hits];
}

// -------------------------------------------------------------------- snapshot

function summarise(snapshot: InventorySnapshot): string[] {
  const findings: string[] = [];
  const { counts, capture } = snapshot;

  // Group by rule: one Slack window drags in half a dozen helper processes, and
  // six near-identical findings hide the one that matters further down the list.
  const byRule = new Map<string, RunningApp[]>();
  for (const app of snapshot.apps.filter(a => a.prohibited)) {
    const rule = app.matchedRule ?? app.name;
    byRule.set(rule, [...(byRule.get(rule) ?? []), app]);
  }
  for (const [rule, matched] of byRule) {
    const lead = matched.find(a => a.kind === 'foreground') ?? matched[0];
    const others = matched.length - 1;
    findings.push(
      `Prohibited application running: ${lead.name}` +
      `${lead.pid ? ` (pid ${lead.pid})` : ''} — matched rule "${rule}"` +
      `${others > 0 ? ` and ${others} related process(es)` : ''}`
    );
  }
  for (const device of snapshot.peripherals.filter(d => d.flagged)) {
    findings.push(`Flagged device: ${device.name} — ${device.reason}`);
  }
  if (!capture.contentProtection) {
    findings.push('Content protection is OFF — the exam window would appear in screenshots.');
  }
  if (!capture.screenshotsBlocked && process.platform === 'darwin') {
    findings.push('System-wide screenshots are still enabled.');
  }
  for (const recorder of capture.recordersRunning) {
    findings.push(`Screen recorder or remote-access app running: ${recorder}`);
  }
  for (const cam of capture.virtualCameras) {
    findings.push(`Virtual camera installed: ${cam} — the proctoring feed can be faked.`);
  }
  if (counts.foregroundApps > 1) {
    findings.push(
      `${counts.foregroundApps} applications have windows open; only the secure browser should.`
    );
  }
  return findings;
}

/** Take one full read-only picture of the machine. */
export function takeSnapshot(reason: string, options: InventoryOptions): InventorySnapshot {
  const apps = process.platform === 'darwin' ? macApps()
    : process.platform === 'win32' ? windowsApps()
    : [];
  markProhibited(apps, options.prohibitedProcesses);

  const peripherals = process.platform === 'darwin' ? macPeripherals()
    : process.platform === 'win32' ? windowsPeripherals()
    : [];

  const capture: CaptureStatus = {
    contentProtection: options.contentProtection,
    screenshotsBlocked: screenshotsBlocked(),
    screenshotDir: process.platform === 'darwin' ? screenshotDir() : 'n/a',
    screenRecordingPermission: options.screenRecordingPermission,
    recordersRunning: runningRecorders(),
    virtualCameras: peripherals
      .filter(d => d.category === 'camera' && d.flagged)
      .map(d => d.name)
  };

  const snapshot: InventorySnapshot = {
    at: Date.now(),
    reason,
    host: os.hostname(),
    user: os.userInfo().username,
    platform: process.platform,
    osRelease: os.release(),
    arch: process.arch,
    counts: {
      foregroundApps: apps.filter(a => a.kind === 'foreground').length,
      menuBarAgents: apps.filter(a => a.kind === 'agent').length,
      backgroundDaemons: apps.filter(a => a.kind === 'background').length,
      totalProcesses: totalProcessCount(apps.length),
      prohibitedApps: apps.filter(a => a.prohibited).length,
      externalDevices: peripherals.filter(d => d.external).length,
      flaggedDevices: peripherals.filter(d => d.flagged).length
    },
    apps,
    peripherals,
    capture,
    findings: [],
    clean: false
  };

  snapshot.findings = summarise(snapshot);
  snapshot.clean = snapshot.findings.length === 0;
  return snapshot;
}
