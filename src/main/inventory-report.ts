/**
 * Inventory report — the plain-text evidence file an invigilator reads.
 *
 * One file, appended to. Every snapshot is a self-contained block, so the file
 * is still useful if the session ends badly and only the first block was
 * written. Fixed-width columns on purpose: this gets opened in Notepad and
 * TextEdit, pasted into tickets, and grepped — not parsed.
 */
import * as fs from 'fs';
import * as path from 'path';
import type { InventorySnapshot, Peripheral, RunningApp } from './system-inventory';
import type { Violation } from './capture-guard';

const WIDTH = 88;
const RULE = '='.repeat(WIDTH);

function section(title: string): string {
  return `\n-- ${title} ${'-'.repeat(Math.max(0, WIDTH - title.length - 4))}`;
}

function field(label: string, value: string | number): string {
  return `${label.padEnd(22)}: ${value}`;
}

function stamp(ms: number): string {
  const d = new Date(ms);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
         `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function appRows(apps: RunningApp[]): string[] {
  if (!apps.length) return ['  (none)'];
  const lines = [
    '  ' + 'STATUS'.padEnd(12) + 'APPLICATION'.padEnd(34) + 'PID'.padEnd(8) + 'IDENTIFIER',
    '  ' + '-'.repeat(WIDTH - 4)
  ];
  for (const app of apps) {
    lines.push(
      '  ' +
      (app.prohibited ? 'PROHIBITED' : 'ok').padEnd(12) +
      app.name.slice(0, 33).padEnd(34) +
      String(app.pid ?? '-').padEnd(8) +
      (app.bundleId ?? '-')
    );
  }
  return lines;
}

function deviceRows(devices: Peripheral[]): string[] {
  if (!devices.length) return ['  (none detected)'];
  const lines = [
    '  ' + 'STATUS'.padEnd(10) + 'TYPE'.padEnd(11) + 'DEVICE'.padEnd(36) + 'DETAIL',
    '  ' + '-'.repeat(WIDTH - 4)
  ];
  for (const device of devices) {
    lines.push(
      '  ' +
      (device.flagged ? 'FLAGGED' : device.external ? 'external' : 'built-in').padEnd(10) +
      device.category.padEnd(11) +
      device.name.slice(0, 35).padEnd(36) +
      device.detail
    );
    if (device.reason) lines.push('  ' + ' '.repeat(21) + `↳ ${device.reason}`);
  }
  return lines;
}

/** Render one snapshot as the block that gets appended to the report file. */
export function renderSnapshot(
  snapshot: InventorySnapshot,
  index: number,
  violations: Violation[]
): string {
  const { counts, capture } = snapshot;
  const out: string[] = [];

  out.push('', RULE);
  out.push(`SNAPSHOT ${index}  —  ${snapshot.reason}`);
  out.push(RULE);
  out.push(field('Captured at', stamp(snapshot.at)));
  out.push(field('Machine', `${snapshot.host} (${snapshot.platform} ${snapshot.osRelease} ${snapshot.arch})`));
  out.push(field('Logged-in user', snapshot.user));
  out.push(field('Verdict', snapshot.clean
    ? 'CLEAN — nothing flagged'
    : `${snapshot.findings.length} finding(s) — see FINDINGS below`));

  out.push(section('COUNTS'));
  out.push(field('Apps with windows', counts.foregroundApps));
  out.push(field('Menu-bar agents', counts.menuBarAgents));
  out.push(field('Background daemons', counts.backgroundDaemons));
  out.push(field('Total OS processes', counts.totalProcesses));
  out.push(field('Prohibited apps', counts.prohibitedApps));
  out.push(field('External devices', counts.externalDevices));
  out.push(field('Flagged devices', counts.flaggedDevices));

  out.push(section('APPLICATIONS WITH WINDOWS OPEN'));
  out.push(...appRows(snapshot.apps.filter(a => a.kind === 'foreground')));

  const hiddenProhibited = snapshot.apps.filter(a => a.prohibited && a.kind !== 'foreground');
  if (hiddenProhibited.length) {
    out.push(section('PROHIBITED APPS RUNNING WITHOUT A WINDOW'));
    out.push(...appRows(hiddenProhibited));
  }

  out.push(section('CONNECTED DEVICES'));
  out.push(...deviceRows(snapshot.peripherals));

  out.push(section('SCREEN CAPTURE & RECORDING'));
  out.push(field('Window capture-proof', capture.contentProtection
    ? 'YES — exam window is excluded from all capture'
    : 'NO — exam window would appear in screenshots'));
  out.push(field('System screenshots', capture.screenshotsBlocked
    ? 'BLOCKED by this app'
    : 'ENABLED'));
  out.push(field('Screenshot folder', capture.screenshotDir));
  out.push(field('Screen-rec permission', capture.screenRecordingPermission));
  out.push(field('Recorders running', capture.recordersRunning.join(', ') || 'none'));
  out.push(field('Virtual cameras', capture.virtualCameras.join(', ') || 'none'));

  out.push(section('FINDINGS'));
  if (snapshot.clean) {
    out.push('  None. The machine is in an acceptable state for the exam.');
  } else {
    snapshot.findings.forEach((f, i) => out.push(`  ${String(i + 1).padStart(2)}. ${f}`));
  }

  out.push(section('CAPTURE VIOLATIONS RECORDED SINCE LAST SNAPSHOT'));
  if (!violations.length) {
    out.push('  None.');
  } else {
    for (const v of violations) out.push(`  [${stamp(v.at)}] ${v.kind}: ${v.detail}`);
  }
  out.push('');

  return out.join('\n');
}

/** Appends snapshots to one text file, creating it with a header on first use. */
export class InventoryReport {
  private index = 0;

  constructor(private readonly filePath: string) {}

  get path(): string {
    return this.filePath;
  }

  /** Start a fresh file for this exam session. */
  begin(appName: string, examUrl: string): void {
    const header = [
      RULE,
      `${appName} — SYSTEM INVENTORY REPORT`,
      RULE,
      field('Session started', stamp(Date.now())),
      field('Exam URL', examUrl),
      field('Report file', this.filePath),
      '',
      'Read-only record of what was running and plugged in during this exam.',
      'No process was killed and no file was deleted to produce it.',
      ''
    ].join('\n');
    this.write(header, 'w');
  }

  /** Append one snapshot; returns the index it was written under. */
  append(snapshot: InventorySnapshot, violations: Violation[]): number {
    this.index += 1;
    this.write(renderSnapshot(snapshot, this.index, violations), 'a');
    return this.index;
  }

  /** Close the file with a summary line. */
  end(totalViolations: number): void {
    this.write(
      ['', RULE,
       `SESSION ENDED ${stamp(Date.now())} — ${this.index} snapshot(s), ` +
       `${totalViolations} capture violation(s) recorded.`,
       RULE, ''].join('\n'),
      'a'
    );
  }

  private write(text: string, flag: 'w' | 'a'): void {
    try {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
      fs.writeFileSync(this.filePath, text, { encoding: 'utf-8', flag });
    } catch (err) {
      console.warn(`[REPORT] cannot write ${this.filePath}:`, err);
    }
  }
}
