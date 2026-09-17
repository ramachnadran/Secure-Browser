/**
 * Exit guard — the only supported way out of a running exam.
 *
 * The window is a kiosk, so quitting has to be possible: a student whose
 * machine misbehaves must not be trapped, and an invigilator must be able to
 * end a session. What must NOT be possible is the student quitting alone.
 *
 * The shortcut therefore opens a prompt for an invigilator code instead of
 * exiting. The code is stored as a SHA-256 hash so the config file never
 * carries it in the clear, and every failed attempt is recorded as a
 * violation, because a student trying codes is itself worth knowing about.
 *
 * This is not a secret-keeping mechanism. A determined student can still force
 * quit at the OS level, and that is deliberate — the report records the
 * session ending early, which is the signal an invigilator actually needs.
 */
import { BrowserWindow, ipcMain } from 'electron';
import { createHash, timingSafeEqual } from 'crypto';
import * as path from 'path';

type ViolationSink = (kind: string, detail: string) => void;

const MAX_ATTEMPTS = 3;

export interface ExitGuardOptions {
  /** SHA-256 of the invigilator code, lower-case hex. Empty disables exit. */
  codeHash: string;
  /** Allow quitting with no code at all. Dev builds only, never packaged. */
  allowUnprotectedExit: boolean;
  preloadPath: string;
  promptPath: string;
  report: ViolationSink;
  onExitApproved: () => void;
}

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf-8').digest('hex');
}

/** Constant-time compare so attempts cannot be timed to leak the code. */
function hashesMatch(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf-8');
  const right = Buffer.from(b, 'utf-8');
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

export class ExitGuard {
  private prompt: BrowserWindow | null = null;
  private attempts = 0;

  constructor(private readonly options: ExitGuardOptions) {
    ipcMain.handle('secure:submit-exit-code', (_e, code: unknown) => this.verify(code));
    ipcMain.handle('secure:cancel-exit', () => { this.close(); return { ok: true }; });
    ipcMain.handle('secure:exit-attempts-left', () => ({
      left: Math.max(0, MAX_ATTEMPTS - this.attempts)
    }));
  }

  /** True when this build has no way to exit without a code. */
  get isProtected(): boolean {
    return !this.options.allowUnprotectedExit && this.options.codeHash.length > 0;
  }

  /**
   * Handle the exit shortcut. Returns whether the keystroke was consumed, so
   * the caller can fall through to its own handling when it was not.
   */
  requestExit(parent: BrowserWindow | null): boolean {
    if (this.options.allowUnprotectedExit) {
      console.warn('[SECURITY] unprotected exit — dev build only');
      this.options.onExitApproved();
      return true;
    }

    if (!this.options.codeHash) {
      // Refusing outright would trap the student, so record it and hold the
      // session open. Shipping without a code is a configuration error.
      this.options.report(
        'exit-attempt-no-code-configured',
        'exit shortcut pressed but no invigilator code is configured'
      );
      return true;
    }

    this.openPrompt(parent);
    return true;
  }

  private openPrompt(parent: BrowserWindow | null): void {
    if (this.prompt) { this.prompt.focus(); return; }
    if (this.attempts >= MAX_ATTEMPTS) {
      this.options.report('exit-attempts-exhausted', `${MAX_ATTEMPTS} failed codes; prompt locked`);
      return;
    }

    this.prompt = new BrowserWindow({
      width: 380,
      height: 260,
      parent: parent ?? undefined,
      modal: true,
      resizable: false,
      minimizable: false,
      maximizable: false,
      fullscreenable: false,
      alwaysOnTop: true,
      frame: false,
      show: false,
      webPreferences: {
        preload: this.options.preloadPath,
        contextIsolation: true,
        nodeIntegration: false,
        sandbox: true,
        devTools: false
      }
    });

    // The prompt sits above a capture-protected window; it must be too.
    this.prompt.setContentProtection(true);
    this.prompt.loadFile(this.options.promptPath);
    this.prompt.once('ready-to-show', () => this.prompt?.show());
    this.prompt.on('closed', () => { this.prompt = null; });
  }

  private verify(code: unknown): { ok: boolean; left: number; locked: boolean } {
    if (typeof code !== 'string' || !code) {
      return { ok: false, left: MAX_ATTEMPTS - this.attempts, locked: false };
    }

    if (hashesMatch(sha256(code), this.options.codeHash.toLowerCase())) {
      this.options.report('exit-approved', 'invigilator code accepted; session ended');
      this.close();
      this.options.onExitApproved();
      return { ok: true, left: MAX_ATTEMPTS - this.attempts, locked: false };
    }

    this.attempts += 1;
    const left = Math.max(0, MAX_ATTEMPTS - this.attempts);
    this.options.report('exit-code-rejected', `wrong invigilator code, ${left} attempt(s) left`);
    if (left === 0) this.close();
    return { ok: false, left, locked: left === 0 };
  }

  private close(): void {
    if (!this.prompt) return;
    const prompt = this.prompt;
    this.prompt = null;
    if (!prompt.isDestroyed()) prompt.close();
  }
}

export { sha256 as hashExitCode };
