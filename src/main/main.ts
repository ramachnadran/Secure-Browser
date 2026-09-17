/**
 * Ei Secure Browser — main process (Phase 1 MVP + system inventory).
 *
 * Responsibilities in this phase:
 *  - Launch a single, fullscreen KIOSK window (no OS chrome, no menu).
 *  - Show the app's own launch screen, then load the exam URL (asset_dynamic).
 *  - Apply browser-level LOCKDOWN: block new windows, off-domain navigation,
 *    DevTools, reload, print, save, view-source and clipboard shortcuts.
 *  - Exclude the window from screen capture / recording / sharing, and disable
 *    system-wide screenshots for the duration of the exam.
 *  - Inventory the machine (running apps, connected peripherals, capture state)
 *    and write it to a plain-text report for the invigilator.
 *
 * NOT in this phase (needs the native OS module — Phase 3):
 *  - OS-level Alt-Tab / Cmd-Tab / Win-key blocking, process kill.
 */
import { app, BrowserWindow, Menu, ipcMain, systemPreferences } from 'electron';
import * as fs from 'fs';
import * as path from 'path';
import { CaptureGuard, Violation } from './capture-guard';
import { ExitGuard } from './exit-guard';
import { InventoryReport } from './inventory-report';
import { InventorySnapshot, takeSnapshot } from './system-inventory';

interface InventoryConfig {
  /** Report location, relative to the app root unless absolute. */
  reportFile: string;
  /** How often to re-scan while the exam is open. 0 disables re-scanning. */
  snapshotIntervalMs: number;
  /** Turn system-wide screenshots off for the duration of the exam. */
  blockScreenshots: boolean;
  /** Refuse to load the exam while the pre-flight scan has findings. */
  blockExamOnFindings: boolean;
  /** Case-insensitive substrings matched against app name and bundle id. */
  prohibitedProcesses: string[];
}

interface ExitConfig {
  /**
   * SHA-256 of the invigilator code, lower-case hex. Never the code itself.
   * Generate one with: node -e "console.log(require('crypto').createHash('sha256').update('YOUR-CODE').digest('hex'))"
   */
  codeSha256: string;
}

interface AppConfig {
  appName: string;
  examUrl: string;
  allowedDomains: string[];
  inventory: InventoryConfig;
  exit: ExitConfig;
}

const DEFAULT_CONFIG: AppConfig = {
  appName: 'Ei Secure Browser',
  examUrl: 'https://test.assetdynamic.in/asset_dynamic/asset/testForm.php',
  allowedDomains: ['assetdynamic.in', 'educationalinitiatives.com', 'assetonline.in', 'amazonaws.com'],
  inventory: {
    reportFile: 'reports/system-inventory.txt',
    snapshotIntervalMs: 120000,
    blockScreenshots: true,
    blockExamOnFindings: false,
    prohibitedProcesses: []
  },
  exit: { codeSha256: '' }
};

function loadConfig(): AppConfig {
  try {
    const raw = fs.readFileSync(path.join(app.getAppPath(), 'config', 'app-config.json'), 'utf-8');
    const parsed = JSON.parse(raw);
    // Merge one level deep so a partial "inventory" block keeps the defaults.
    return {
      ...DEFAULT_CONFIG,
      ...parsed,
      inventory: { ...DEFAULT_CONFIG.inventory, ...(parsed.inventory ?? {}) },
      exit: { ...DEFAULT_CONFIG.exit, ...(parsed.exit ?? {}) }
    };
  } catch {
    return DEFAULT_CONFIG;
  }
}

const config = loadConfig();
const isDev = process.argv.includes('--dev');
let mainWindow: BrowserWindow | null = null;
let contentProtectionOn = false;
let snapshotTimer: NodeJS.Timeout | null = null;
let shuttingDown = false;

/** Violations seen since the last snapshot was written to the report. */
let pendingViolations: Violation[] = [];
let totalViolations = 0;

function isAllowedUrl(url: string): boolean {
  if (url.startsWith('file://')) return true; // our own launch screen
  try {
    const host = new URL(url).hostname;
    return config.allowedDomains.some(d => host === d || host.endsWith('.' + d));
  } catch {
    return false;
  }
}

// Single-instance lock — a second copy must not run during an exam.
if (!app.requestSingleInstanceLock()) {
  app.quit();
}

/**
 * Capture attempts cannot always be PREVENTED (WindowServer owns the hotkeys),
 * and content protection already makes the resulting image blank. What is left,
 * and what the invigilator actually needs, is a RECORD that the student tried.
 */
function reportViolation(kind: string, detail: string) {
  const violation: Violation = { kind, detail, at: Date.now() };
  pendingViolations.push(violation);
  totalViolations += 1;
  console.warn(`[SECURITY] ${kind}: ${detail}`);
  mainWindow?.webContents.send('secure:violation', violation);
}

/**
 * The report belongs in the repo when running from source, which is where an
 * engineer looks for it. A packaged app runs from a read-only asar, so fall
 * back to the per-user data directory and log where it went.
 */
function resolveReportPath(): string {
  const configured = config.inventory.reportFile;
  if (path.isAbsolute(configured)) return configured;

  const inRepo = path.join(app.getAppPath(), configured);
  try {
    fs.mkdirSync(path.dirname(inRepo), { recursive: true });
    fs.accessSync(path.dirname(inRepo), fs.constants.W_OK);
    return inRepo;
  } catch {
    return path.join(app.getPath('userData'), configured);
  }
}

const report = new InventoryReport(resolveReportPath());
const guard = new CaptureGuard(
  path.join(app.getPath('userData'), 'capture-guard-restore.json'),
  reportViolation
);

/**
 * Unprotected exit survives only in a dev build running from source. A
 * packaged app always demands the code, whatever flags it was started with,
 * so `--dev` on a shipped binary buys a student nothing.
 */
const exitGuard = new ExitGuard({
  codeHash: config.exit.codeSha256.trim().toLowerCase(),
  allowUnprotectedExit: isDev && !app.isPackaged,
  preloadPath: path.join(__dirname, '..', 'preload', 'preload.js'),
  promptPath: path.join(app.getAppPath(), 'renderer', 'quit-prompt.html'),
  report: reportViolation,
  onExitApproved: () => { shutdown(); app.exit(0); }
});

/** macOS only: whether THIS app is allowed to record the screen. */
function screenRecordingPermission(): string {
  if (process.platform !== 'darwin') return 'n/a';
  try {
    return systemPreferences.getMediaAccessStatus('screen');
  } catch {
    return 'unknown';
  }
}

/** Scan the machine, append the result to the report, return the snapshot. */
function scanAndRecord(reason: string): InventorySnapshot {
  const snapshot = takeSnapshot(reason, {
    prohibitedProcesses: config.inventory.prohibitedProcesses,
    contentProtection: contentProtectionOn,
    screenRecordingPermission: screenRecordingPermission()
  });

  const violations = pendingViolations;
  pendingViolations = [];
  const index = report.append(snapshot, violations);

  console.log(
    `[INVENTORY] snapshot ${index} (${reason}): ` +
    `${snapshot.counts.foregroundApps} apps with windows, ` +
    `${snapshot.counts.externalDevices} external device(s), ` +
    `${snapshot.findings.length} finding(s) → ${report.path}`
  );
  return snapshot;
}

function applyLockdown(win: BrowserWindow) {
  const wc = win.webContents;

  // Exclude this window from screen capture: screenshots, screen recording and
  // screen sharing (Zoom/Meet/Teams) all render it blank. This CANNOT be done by
  // blocking keys — macOS consumes Cmd+Shift+3/4/5 in WindowServer before the app
  // sees them, so `before-input-event` never fires for a screenshot.
  // Maps to NSWindowSharingNone (macOS) / WDA_EXCLUDEFROMCAPTURE (Windows).
  // Deliberately NOT gated on isDev — a secure browser must never ship a build
  // where this is off, and it is the one control that cannot be re-added later.
  const protectContent = () => {
    win.setContentProtection(true);
    contentProtectionOn = true;
    console.log('[SECURITY] content protection ON (window excluded from capture)');
  };
  protectContent();
  // macOS can drop the flag across show / fullscreen transitions — re-apply.
  win.on('show', protectContent);
  win.on('enter-full-screen', protectContent);

  // Deny popups / new windows entirely.
  wc.setWindowOpenHandler(() => ({ action: 'deny' }));

  // Block navigation to anything outside the allowed domains.
  wc.on('will-navigate', (e, url) => {
    if (!isAllowedUrl(url)) e.preventDefault();
  });
  wc.on('will-redirect', (e, url) => {
    if (!isAllowedUrl(url)) e.preventDefault();
  });

  // Block risky key combinations — scoped to this window (not system-wide).
  wc.on('before-input-event', (event, input) => {
    if (input.type !== 'keyDown') return;
    const key = (input.key || '').toLowerCase();
    const mod = input.control || input.meta;

    // Ending the session: Ctrl/Cmd+Shift+Q asks for the invigilator code. It
    // never quits on its own — see ExitGuard for why exiting stays possible.
    if (mod && input.shift && key === 'q') {
      event.preventDefault();
      exitGuard.requestExit(win);
      return;
    }

    const blocked =
      (mod && input.shift && key === 'i') || // DevTools
      key === 'f12' ||                        // DevTools
      (mod && key === 'r') ||                 // reload
      (mod && key === 'p') ||                 // print
      (mod && key === 's') ||                 // save page
      (mod && key === 'u') ||                 // view source
      (mod && (key === 'c' || key === 'v' || key === 'x')) || // clipboard
      key === 'printscreen';

    if (blocked && !isDev) event.preventDefault();
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    show: false,
    fullscreen: true,
    kiosk: !isDev,               // true kiosk in production; off in dev so we can escape
    frame: false,
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, '..', 'preload', 'preload.js'),
      contextIsolation: true,    // isolate our bridge from the page
      nodeIntegration: false,    // page can never touch Node
      sandbox: true,             // extra isolation for the loaded exam
      devTools: isDev,
      spellcheck: false
    }
  });

  Menu.setApplicationMenu(null); // no app menu at all
  applyLockdown(mainWindow);

  // Start on the app's own launch screen; the exam loads after "Start".
  mainWindow.loadFile(path.join(app.getAppPath(), 'renderer', 'launch.html'));
  mainWindow.once('ready-to-show', () => mainWindow?.show());
}

/** The launch screen shows this; it must stay small enough to render as a list. */
function toRendererSummary(snapshot: InventorySnapshot) {
  return {
    at: snapshot.at,
    clean: snapshot.clean,
    counts: snapshot.counts,
    findings: snapshot.findings,
    foregroundApps: snapshot.apps
      .filter(a => a.kind === 'foreground')
      .map(a => ({ name: a.name, prohibited: a.prohibited })),
    devices: snapshot.peripherals
      .filter(d => d.external || d.flagged)
      .map(d => ({ name: d.name, category: d.category, flagged: d.flagged, reason: d.reason })),
    capture: snapshot.capture,
    reportPath: report.path
  };
}

// Renderer (launch screen) → app info, pre-flight scan, start the exam.
ipcMain.handle('secure:get-config', () => ({
  appName: config.appName,
  blockExamOnFindings: config.inventory.blockExamOnFindings
}));

ipcMain.handle('secure:scan-system', () => toRendererSummary(scanAndRecord('pre-flight check')));

// The floating exit button in the corner of every page. Quits straight away,
// no invigilator code — asked for explicitly. The exit is still recorded, so
// the report shows who left and when even though nothing stopped them.
ipcMain.handle('secure:request-exit', () => {
  reportViolation('exit-button-used', 'student ended the session with the exit button');
  shutdown();
  app.exit(0);
  return { ok: true };
});

ipcMain.handle('secure:start-exam', () => {
  if (!mainWindow) return { ok: false, reason: 'no window' };

  const snapshot = scanAndRecord('exam start');
  if (config.inventory.blockExamOnFindings && !snapshot.clean) {
    return { ok: false, reason: 'blocked', findings: snapshot.findings };
  }

  mainWindow.loadURL(config.examUrl);

  // Keep scanning during the exam — a device plugged in at minute 20 matters
  // just as much as one plugged in before the start.
  const interval = config.inventory.snapshotIntervalMs;
  if (interval > 0 && !snapshotTimer) {
    snapshotTimer = setInterval(() => {
      const during = scanAndRecord('during exam');
      mainWindow?.webContents.send('secure:inventory', toRendererSummary(during));
    }, interval);
  }
  return { ok: true, findings: snapshot.findings };
});

/** Restore the machine and close the report. Safe to call more than once. */
function shutdown() {
  if (shuttingDown) return;
  shuttingDown = true;
  if (snapshotTimer) {
    clearInterval(snapshotTimer);
    snapshotTimer = null;
  }
  guard.shutdown();
  report.end(totalViolations);
  console.log(`[REPORT] written to ${report.path}`);
}

/** The code shipped in the repo. Real deployments must replace it. */
const SAMPLE_EXIT_CODE_HASH = '448d0e10f2935e07da7176c2c329a5c906715a051ae6a8a3e4412690c6acecac';

app.whenReady().then(() => {
  if (isDev && !app.isPackaged) {
    console.warn('[SECURITY] dev build — the exit shortcut quits without a code');
  } else if (!config.exit.codeSha256.trim()) {
    console.warn('[SECURITY] no invigilator code configured — the exit shortcut is inert');
  } else if (config.exit.codeSha256.trim().toLowerCase() === SAMPLE_EXIT_CODE_HASH) {
    console.warn('[SECURITY] still using the sample invigilator code — set your own before shipping');
  }

  // Undo a previous run that was force-quit before it could clean up.
  guard.recoverFromCrash();

  report.begin(config.appName, config.examUrl);
  createWindow();

  if (config.inventory.blockScreenshots) guard.blockScreenshots();
  guard.watchScreenshotFolder();
  guard.watchForRecorders(5000);

  // First scan happens now so the launch screen has something to show.
  scanAndRecord('app launch');

  app.on('second-instance', () => mainWindow?.focus());
});

app.on('before-quit', shutdown);
app.on('window-all-closed', () => app.quit());

// A kiosk app gets killed in ways Electron's own lifecycle never sees.
for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP'] as const) {
  process.on(signal, () => { shutdown(); process.exit(0); });
}
process.on('uncaughtException', err => {
  console.error('[FATAL]', err);
  shutdown();
  process.exit(1);
});
