import type { PackageVersion } from './lockfile.js';

const BASE = 'https://api.osv.dev/v1';
const BATCH_SIZE = 100;

export type OsvSeverity = { type: string; score: string };

export interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  modified?: string;
  aliases?: string[];
  severity?: OsvSeverity[];
  database_specific?: { severity?: string };
  affected?: Array<{
    package?: {
      name?: string;
      ecosystem?: string
    };
    ranges?: Array<{
      type: string; events:
      Array<{
        introduced?: string; fixed?:
        string; last_affected?: string
      }>
    }>
  }>;
  references?: Array<{
    type: string; url: string
  }>;
}

export interface Finding {
  package: PackageVersion; vulnerability: OsvVulnerability
}

async function postJson<T>(url: string, body: unknown): Promise<T> {

  for (let attempt = 0; attempt < 3; attempt++) {
    const response = await fetch(url, {
      method: 'POST', headers: { 'content-type': 'application/json', 'user-agent': 'vulnwatch-cli/0.1' },
      body: JSON.stringify(body), signal: AbortSignal.timeout(20_000)
    });

    if ((response.status === 429 || response.status >= 500) && attempt < 2) {
      await new Promise(r => setTimeout(r, 500 * 2 ** attempt));
      continue;
    }

    if (!response.ok)
      throw new Error(`OSV API error ${response.status}: ${await response.text().then(t => t.slice(0, 200))}`);

    return response.json() as Promise<T>;
  }
  throw new Error('OSV request failed after retries');
}

export async function queryOsv(packages: PackageVersion[]): Promise<Finding[]> {

  const results: Finding[] = [];
  const details = new Map<string, OsvVulnerability>();

  for (let start = 0; start < packages.length; start += BATCH_SIZE) {

    const chunk = packages.slice(start, start + BATCH_SIZE);

    const data = await postJson<{ results: Array<{ vulns?: Array<{ id: string }> }> }>(`${BASE}/querybatch`, {
      queries: chunk.map(p => ({
        package: {
          name: p.name,
          ecosystem: 'npm'
        },
        version: p.version
      }))
    });

    if (!Array.isArray(data.results) || data.results.length !== chunk.length)
      throw new Error('Unexpected OSV batch response; scan incomplete.');

    for (let i = 0; i < chunk.length; i++) {
      for (const match of data.results[i].vulns ?? []) {
        if (!details.has(match.id)) {
          const detail = await getVulnerability(match.id);
          details.set(match.id, detail);
        }
        results.push({ package: chunk[i], vulnerability: details.get(match.id)! });
      }
    }
  }

  return results;
}

async function getVulnerability(id: string): Promise<OsvVulnerability> {

  const response = await fetch(`${BASE}/vulns/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(20_000) });

  if (!response.ok)
    throw new Error(`Failed to fetch OSV advisory ${id} (${response.status}); scan incomplete.`);

  return response.json() as Promise<OsvVulnerability>;
}

export function fixedVersions(vuln: OsvVulnerability, packageName: string): string[] {
  const fixes = new Set<string>();
  for (const affected of vuln.affected ?? []) {
    if (affected.package?.ecosystem !== 'npm' || affected.package.name !== packageName) continue;
    for (const range of affected.ranges ?? []) {
      for (const event of range.events)
        if (event.fixed) fixes.add(event.fixed);
    }
  }
  return [...fixes].sort();
}

export function severityLabel(vuln: OsvVulnerability): string {
  return vuln.database_specific?.severity?.toUpperCase() || (vuln.severity?.length ? 'SEE ADVISORY' : 'UNKNOWN');
}
