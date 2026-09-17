/**
 * Capture guard — actually stopping screenshots and recordings, not just noting them.
 *
 * Three layers, weakest last:
 *
 *  1. Content protection (in main.ts). The window is excluded from the capture
 *     pipeline itself, so screenshots, recordings and Zoom/Meet screen shares
 *     all render it blank. This is the layer that cannot be defeated from
 *     userspace, and it is always on.
 *
 *  2. System-wide screenshot disable (here). macOS consumes Cmd+Shift+3/4/5 in
 *     WindowServer before any app sees the keystroke, so a key handler can
 *     never block them — but the same subsystem honours a preference flag.
 *     Setting it stops the capture from happening at all. It is a change to the
 *     student's machine, so it is reverted on quit, on crash, and on the next
 *     launch if this process was killed outright.
 *
 *  3. Filesystem watch (here). Anything that still lands in the screenshot
 *     folder is recorded as a violation with a filename and a timestamp.
 *
 * Nothing here deletes a student's files or kills their processes.
 */
import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { runningRecorders, screenshotDir, screenshotsBlocked } from './system-inventory';

export interface Violation {
  kind: string;
  detail: string;
  at: number;
}

type ViolationSink = (kind: string, detail: string) => void;

const SCREENCAPTURE_DOMAIN = 'com.apple.screencapture';
const DISABLED_KEY = 'disabled';

/** Records what we changed, so a crashed session can still be cleaned up. */
interface RestoreMarker {
  /** The value the key held before we touched it, or null if it was unset. */
  previous: string | null;
  changedAt: number;
}

function run(cmd: string, args: string[]): boolean {
  try {
    execFileSync(cmd, args, { timeout: 8000, stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

function read(cmd: string, args: string[]): string | null {
  try {
    return execFileSync(cmd, args, {
      encoding: 'utf-8', timeout: 8000, stdio: ['ignore', 'pipe', 'ignore']
    }).trim();
  } catch {
    return null;
  }
}

export class CaptureGuard {
  private marker: RestoreMarker | null = null;
  private watchers: fs.FSWatcher[] = [];
  private recorderTimer: NodeJS.Timeout | null = null;
  private readonly reported = new Set<string>();

  constructor(
    private readonly markerPath: string,
    private readonly report: ViolationSink
  ) {}

  /**
   * Undo a previous run that never got to clean up after itself. Call this
   * before anything else at startup — the student's screenshots must not stay
   * disabled because the app was force-quit during the last exam.
   */
  recoverFromCrash(): void {
    if (process.platform !== 'darwin') return;
    let stale: RestoreMarker;
    try {
      stale = JSON.parse(fs.readFileSync(this.markerPath, 'utf-8'));
    } catch {
      return; // no marker — previous run exited cleanly
    }
    this.marker = stale;
    console.warn('[SECURITY] previous session did not clean up; restoring screenshot setting');
    this.restoreScreenshots();
  }

  /**
   * Turn system-wide screenshot capture off. Returns false when the platform
   * has no such switch (Windows, Linux) or the preference write failed — the
   * caller should fall back to detection only.
   */
  blockScreenshots(): boolean {
    if (process.platform !== 'darwin') return false;
    if (this.marker) return true; // already blocked by us

    const previous = read('defaults', ['read', SCREENCAPTURE_DOMAIN, DISABLED_KEY]);
    if (!run('defaults', ['write', SCREENCAPTURE_DOMAIN, DISABLED_KEY, '-bool', 'true'])) {
      console.warn('[SECURITY] could not disable screenshots; detection only');
      return false;
    }

    this.marker = { previous, changedAt: Date.now() };
    try {
      fs.mkdirSync(path.dirname(this.markerPath), { recursive: true });
      fs.writeFileSync(this.markerPath, JSON.stringify(this.marker), 'utf-8');
    } catch {
      /* the in-memory restore still works; only crash recovery is lost */
    }

    // WindowServer caches the preference; SystemUIServer owns the hotkeys.
    run('killall', ['SystemUIServer']);

    const applied = screenshotsBlocked();
    console.log(`[SECURITY] system-wide screenshots ${applied ? 'DISABLED' : 'still enabled'}`);
    return applied;
  }

  /** Put the screenshot preference back exactly as the student had it. */
  restoreScreenshots(): void {
    if (process.platform !== 'darwin' || !this.marker) return;

    if (this.marker.previous === null) {
      run('defaults', ['delete', SCREENCAPTURE_DOMAIN, DISABLED_KEY]);
    } else {
      run('defaults', ['write', SCREENCAPTURE_DOMAIN, DISABLED_KEY, this.marker.previous]);
    }
    run('killall', ['SystemUIServer']);

    this.marker = null;
    try {
      fs.unlinkSync(this.markerPath);
    } catch {
      /* already gone */
    }
    console.log('[SECURITY] screenshot setting restored');
  }

  /**
   * Watch the screenshot folder. Content protection already makes the image
   * blank, but the attempt itself is what the invigilator needs on record.
   */
  watchScreenshotFolder(): void {
    if (process.platform !== 'darwin') return;
    const dir = screenshotDir();
    try {
      const watcher = fs.watch(dir, (_event, filename) => {
        if (!filename || !/\.(png|jpe?g|tiff|pdf|mov|mp4)$/i.test(filename)) return;
        this.report('screen-capture-attempt', `${filename} appeared in ${dir}`);
      });
      this.watchers.push(watcher);
      console.log(`[SECURITY] watching ${dir} for capture files`);
    } catch (err) {
      console.warn(`[SECURITY] cannot watch ${dir}:`, err);
    }
  }

  /**
   * Poll for recorders and remote-access tools. Each distinct app is reported
   * once per session; repeating every tick would drown the activity log.
   */
  watchForRecorders(intervalMs: number): void {
    if (this.recorderTimer) return;
    const scan = () => {
      for (const name of runningRecorders()) {
        if (this.reported.has(name)) continue;
        this.reported.add(name);
        this.report('screen-recorder-running', name);
      }
    };
    scan();
    this.recorderTimer = setInterval(scan, intervalMs);
  }

  /** Release watchers and restore the machine. Safe to call more than once. */
  shutdown(): void {
    if (this.recorderTimer) {
      clearInterval(this.recorderTimer);
      this.recorderTimer = null;
    }
    for (const watcher of this.watchers) {
      try { watcher.close(); } catch { /* already closed */ }
    }
    this.watchers = [];
    this.restoreScreenshots();
  }
}
