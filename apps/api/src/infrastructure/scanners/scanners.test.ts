import { describe, expect, it } from 'vitest';
import { maskSecret, scanContent, shannonEntropy } from './secrets.js';
import { NpmLockParser, PackageJsonParser } from '../manifests/npm.js';
import { assertSafeTarPath } from '../github/extract.js';
import { ScanFailure } from '../../domain/failures.js';

describe('secrets', () => {
  it('masks provider keys and ignores placeholders', () => {
    const findings = scanContent('config.py', 'token = "AKIAIOSFODNN7EXAMPLE"\npassword = "changeme"\n');
    expect(findings.map((finding) => finding.ruleId)).toContain('SECRET_AWS_ACCESS_KEY');
    expect(findings.some((finding) => finding.evidence.masked === 'changeme')).toBe(false);
    expect(maskSecret('AKIAIOSFODNN7EXAMPLE')).not.toContain('IOSFODNN7EXAM');
    expect(shannonEntropy('aaaaaaaaaaaa')).toBeLessThan(1);
  });

  it('finishes long lines quickly', () => {
    const started = Date.now();
    scanContent('a.txt', `${'a'.repeat(5000)}\npassword = "${'a'.repeat(80)}"\n`);
    expect(Date.now() - started).toBeLessThan(200);
  });
});

describe('npm parsers', () => {
  it('reads lockfile versions and manifest precision', () => {
    const locked = new NpmLockParser().parse(JSON.stringify({
      packages: {
        '': { dependencies: { express: '^4.0.0' } },
        'node_modules/express': { version: '4.18.2', dependencies: { qs: '6.11.0' } },
        'node_modules/qs': { version: '6.11.0' },
      },
    }), 'package-lock.json');
    expect(locked.find((pkg) => pkg.name === 'qs')).toMatchObject({ version: '6.11.0', precision: 'lockfile', direct: false });
    const manifest = new PackageJsonParser().parse(JSON.stringify({ dependencies: { express: '^4.18.0' }, devDependencies: { vitest: '1.2.0' } }), 'package.json');
    expect(manifest.find((pkg) => pkg.name === 'express')?.precision).toBe('manifest-range');
    expect(manifest.find((pkg) => pkg.name === 'vitest')).toMatchObject({ precision: 'manifest-pinned', dev: true });
  });
});

describe('archive paths', () => {
  it('rejects traversal, absolute paths, and links', () => {
    expect(() => assertSafeTarPath('../etc/passwd', 'File')).toThrow(ScanFailure);
    expect(() => assertSafeTarPath('/etc/passwd', 'File')).toThrow(ScanFailure);
    expect(() => assertSafeTarPath('src/app.ts', 'SymbolicLink')).toThrow(ScanFailure);
    expect(() => assertSafeTarPath('src/app.ts', 'File')).not.toThrow();
  });
});
