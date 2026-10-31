// @ts-ignore Node.js test-runner types are not installed in this project.
import { test } from 'node:test';
import { parseLockfile } from '../src/lockfile.js';
import { fixedVersions } from '../src/osv.js';

function deepStrictEqual(actual: unknown, expected: unknown): void {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`Expected ${JSON.stringify(actual)} to equal ${JSON.stringify(expected)}`);
  }
}

test('v3 lockfile: scoped and nested packages, deduplication', () => {
  deepStrictEqual(parseLockfile({
    packages: {
      '': { version: '1.0.0' },
      'node_modules/@types/node': { version: '22.1.0' },
      'node_modules/a': { version: '1.0.0' },
      'node_modules/b/node_modules/a': { version: '1.0.0' }
    }
  }), [{ name: '@types/node', version: '22.1.0' }, { name: 'a', version: '1.0.0' }]);
});
test('v1 lockfile: recursive dependencies', () => {
  deepStrictEqual(parseLockfile({ dependencies: { a: { version: '1.0.0', dependencies: { b: { version: '2.0.0' } } } } }),
    [{ name: 'a', version: '1.0.0' }, { name: 'b', version: '2.0.0' }]);
});
test('fixes are restricted to matching npm package', () => {
  deepStrictEqual(fixedVersions({
    id: 'OSV-1', affected: [
      { package: { name: 'a', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.0.0' }] }] },
      { package: { name: 'b', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ fixed: '5.0.0' }] }] }
    ]
  }, 'a'), ['2.0.0']);
});
