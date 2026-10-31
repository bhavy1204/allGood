#!/usr/bin/env node
import { Command, InvalidArgumentError } from 'commander';
import { resolve } from 'node:path';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { readLockfile } from './lockfile.js';
import { queryOsv, fixedVersions, severityLabel, type Finding } from './osv.js';

const program = new Command();

program.name('vulnwatch').description('Scan npm lockfile dependencies against OSV advisories').version('0.1.0');

const stateDir = join(homedir(), '.vulnwatch');
const statePath = join(stateDir, 'state.json');

function positiveInt(value: string): number {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1) throw new InvalidArgumentError('Must be a positive integer');
  return n;
}

async function scan(cwd: string): Promise<Finding[]> {
  const pkgs = await readLockfile(cwd);
  console.error(`Checking ${pkgs.length} unique npm package versions against OSV...`);

  return queryOsv(pkgs);
}


function render(findings: Finding[]): void {
  if (!findings.length) {
    console.log('No known OSV advisories found for scanned npm dependencies. This is not a guarantee of security.'); return;
  }

  for (const { package: pkg, vulnerability: v } of findings) {
    const fixes = fixedVersions(v, pkg.name);
    console.log(`\n[${severityLabel(v)}] ${pkg.name}@${pkg.version} — ${v.id}`);
    console.log(`  ${v.summary || 'See advisory for details'}`);
    console.log(`  Fix events: ${fixes.length ? fixes.join(', ') : 'No fixed version provided'}`);
    console.log(`  Advisory: https://osv.dev/vulnerability/${encodeURIComponent(v.id)}`);
  }

  console.log(`\n${findings.length} affected package/advisory combinations.`);
}


program.command('scan')
  .description('Scan package-lock.json in a project')
  .option('-p, --path <directory>', 'Project directory', '.')
  .option('--json', 'Output machine-readable JSON')
  .option('--fail-on-findings', 'Exit with code 1 if any advisory is found')
  .action(async (opts: { path: string; json?: boolean; failOnFindings?: boolean }) => {
    const findings = await scan(resolve(opts.path));
    if (opts.json) console.log(JSON.stringify({ findings, count: findings.length }, null, 2));
    else render(findings);
    if (opts.failOnFindings && findings.length) process.exitCode = 1;
  });


program.command('watch')
  .description('Scan once and report only newly detected advisories (schedule via cron)')
  .option('-p, --path <directory>', 'Project directory', '.')
  .option('--notify-webhook <url>', 'Optional HTTPS webhook receiving JSON on new findings')
  .action(async (opts: { path: string; notifyWebhook?: string }) => {
    const cwd = resolve(opts.path);
    const findings = await scan(cwd);
    let state: Record<string, string[]> = {};
    try { state = JSON.parse(await readFile(statePath, 'utf8')) as Record<string, string[]>; }
    catch (e) { if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e; }
    const keys = findings.map(f => `${f.package.name}@${f.package.version}:${f.vulnerability.id}`);
    const old = new Set(state[cwd] ?? []);
    const fresh = findings.filter((_, i) => !old.has(keys[i]));
    if (fresh.length) {
      render(fresh);
      if (opts.notifyWebhook) {
        const url = new URL(opts.notifyWebhook);
        if (url.protocol !== 'https:') throw new Error('Webhook URL must use HTTPS');
        const response = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ project: cwd, findings: fresh }), signal: AbortSignal.timeout(15_000) });
        if (!response.ok) throw new Error(`Webhook returned HTTP ${response.status}; notification not acknowledged`);
      }
    } else console.log('No new advisories since last successful scan.');
    state[cwd] = keys;
    await mkdir(stateDir, { recursive: true, mode: 0o700 });
    await writeFile(statePath, JSON.stringify(state, null, 2), { mode: 0o600 });
  });


program.command('doctor').description('Check project prerequisites').option('-p, --path <directory>', 'Project directory', '.')
  .action(async (opts: { path: string }) => { const pkgs = await readLockfile(resolve(opts.path)); console.log(`OK: Found ${pkgs.length} unique installed npm package versions.`); });


program.command('help-schedule').description('Print example cron schedule').action(() => {
  console.log('Every 6 hours (replace paths):\n0 */6 * * * /absolute/path/to/vulnwatch watch --path /absolute/path/to/project >> /absolute/path/to/vulnwatch.log 2>&1');
});


program.parseAsync()
  .catch(error => {
    console.error(`Error: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 2;
  });
