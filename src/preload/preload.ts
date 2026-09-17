/**
 * Preload — the ONLY bridge between the locked-down page and the main process.
 * Runs with contextIsolation, so the page cannot reach Node/Electron directly;
 * it only sees the small, explicit `window.secureBrowser` API exposed here.
 */
import { contextBridge, ipcRenderer } from 'electron';

interface Violation { kind: string; detail: string; at: number }

contextBridge.exposeInMainWorld('secureBrowser', {
  getConfig: () => ipcRenderer.invoke('secure:get-config'),
  startExam: () => ipcRenderer.invoke('secure:start-exam'),

  /**
   * Run the pre-flight machine scan: running apps, connected peripherals and
   * screen-capture state. Resolves with the same summary that is written to
   * the invigilator's report file.
   */
  scanSystem: () => ipcRenderer.invoke('secure:scan-system'),

  // Screen-capture / recorder attempts detected by the main process. The exam page
  // can subscribe and post these to the proctoring backend as activity-log events.
  onViolation: (cb: (v: Violation) => void) =>
    ipcRenderer.on('secure:violation', (_e, v) => cb(v)),

  // Periodic re-scans taken while the exam is open, for the same activity log.
  onInventory: (cb: (summary: unknown) => void) =>
    ipcRenderer.on('secure:inventory', (_e, s) => cb(s)),

  // Invigilator-code prompt. Only the prompt window ever calls these; the exam
  // page can too, and gains nothing — the code is verified in the main process.
  submitExitCode: (code: string) => ipcRenderer.invoke('secure:submit-exit-code', code),
  cancelExit: () => ipcRenderer.invoke('secure:cancel-exit')
});

/**
 * Floating exit button, top right of every page.
 *
 * The window is frameless and kiosk, so there is no OS close button. Clicking
 * this quits immediately, with no invigilator code. That is deliberate and was
 * asked for; note it means the code prompt on the keyboard shortcut no longer
 * protects anything, since this button is always on screen beside it.
 *
 * It lives in a shadow root so the exam page's own CSS cannot restyle or hide
 * it by accident, and it is skipped on the prompt window itself.
 */
function mountExitButton(): void {
  if (location.pathname.endsWith('quit-prompt.html')) return;
  if (document.getElementById('ei-secure-exit')) return;

  const host = document.createElement('div');
  host.id = 'ei-secure-exit';
  host.style.cssText =
    'position:fixed;top:0;right:0;z-index:2147483647;width:auto;height:auto;' +
    'margin:0;padding:0;border:0;pointer-events:none;';

  const root = host.attachShadow({ mode: 'closed' });
  const style = document.createElement('style');
  style.textContent = `
    button {
      pointer-events: auto;
      margin: 12px 14px 0 0;
      display: inline-flex; align-items: center; gap: 7px;
      font: 600 12.5px/1 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      color: #16242c; background: rgba(255,255,255,.92);
      border: 1px solid rgba(22,36,44,.16); border-radius: 8px;
      padding: 9px 13px; cursor: pointer;
      box-shadow: 0 2px 10px rgba(16,36,42,.16);
      -webkit-backdrop-filter: blur(6px); backdrop-filter: blur(6px);
    }
    button:hover  { background: #fff; border-color: rgba(22,36,44,.3); }
    button:active { transform: translateY(1px); }
    button:focus-visible { outline: 2px solid #1f6f6a; outline-offset: 2px; }
    svg { width: 13px; height: 13px; }
  `;

  const button = document.createElement('button');
  button.type = 'button';
  button.title = 'End the secure session and quit';
  button.innerHTML =
    '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.7" ' +
    'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<path d="M6 14H3a1 1 0 0 1-1-1V3a1 1 0 0 1 1-1h3"/>' +
    '<path d="M10.5 11 14 8l-3.5-3"/><path d="M14 8H6"/></svg>';
  button.appendChild(document.createTextNode('Exit exam'));
  button.addEventListener('click', () => { ipcRenderer.invoke('secure:request-exit'); });

  root.appendChild(style);
  root.appendChild(button);
  document.body.appendChild(host);
}

if (document.readyState === 'loading') {
  window.addEventListener('DOMContentLoaded', mountExitButton);
} else {
  mountExitButton();
}

// Disable the right-click context menu everywhere inside the app.
window.addEventListener('contextmenu', (e) => e.preventDefault());
// Disable text selection drag on the app's own chrome (exam content still works).
window.addEventListener('dragstart', (e) => e.preventDefault());
