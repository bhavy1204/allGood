import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

export interface PackageVersion {
  name: string; version: string
}


type LockEntry = {
  name?: string;
  version?: string;
  dependencies?: Record<string, LockEntry>
};

type Lockfile = {
  lockfileVersion?: number;
  packages?: Record<string, LockEntry>;
  dependencies?: Record<string, LockEntry>
};

export function parseLockfile(lock: Lockfile): PackageVersion[] {

  const seen = new Set<string>();
  const found: PackageVersion[] = [];

  const add = (name: string, version?: string) => {
    if (!name || !version || !/^\d+\.\d+\.\d+/.test(version))
      return;

    const key = `${name}\0${version}`;
    
    if (!seen.has(key)) {
      seen.add(key);
      found.push({ name, version });
    }

  };


  if (lock.packages && Object.keys(lock.packages).length) {

    for (const [path, entry] of Object.entries(lock.packages)) {

      if (!path)
        continue; // root project, not an installed dependency

      const name = entry.name || path.split('node_modules/').at(-1)!;

      add(name, entry.version);
    }
  } else {
    const walk = (dependencies: Record<string, LockEntry> = {}) => {
      for (const [name, entry] of Object.entries(dependencies)) {
        add(name, entry.version);
        walk(entry.dependencies);
      }
    };
    walk(lock.dependencies);
  }

  return found.sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
}

export async function readLockfile(cwd: string): Promise<PackageVersion[]> {

  const filename = resolve(cwd, 'package-lock.json');
  let content: string;

  try {
    content = await readFile(filename, 'utf8');
  }
  catch {
    throw new Error(`Cannot read ${filename}. Choose a project containing package-lock.json.`);
  }

  let parsed: Lockfile;

  try {
    parsed = JSON.parse(content) as Lockfile;
  }

  catch {
    throw new Error(`Invalid JSON in ${filename}`);
  }

  if (!parsed.packages && !parsed.dependencies)
    throw new Error('Unsupported package-lock.json structure.');


  return parseLockfile(parsed);

}




