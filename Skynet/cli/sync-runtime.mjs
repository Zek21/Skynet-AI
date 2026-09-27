#!/usr/bin/env node

import { createHash } from 'node:crypto';
import {
    copyFileSync,
    existsSync,
    mkdirSync,
    readFileSync,
    writeFileSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const TOOLS = [
    'skynet_provider_oauth.py',
    'skynet_public_release_gate.py',
    'skynet_npm_publish_gate.py',
    'skynet_publish_boundary_guard.py',
];

const packageDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(packageDir, '..', '..');
const sourceDir = join(repoRoot, 'tools');
const runtimeDir = join(packageDir, 'runtime');
const manifestPath = join(runtimeDir, 'manifest.json');
const checkOnly = process.argv.slice(2).includes('--check');

function sha256(path) {
    return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function expectedManifest() {
    const files = {};
    for (const name of TOOLS) {
        const source = join(sourceDir, name);
        if (!existsSync(source)) {
            throw new Error(`runtime source missing: ${source}`);
        }
        files[name] = sha256(source);
    }
    return {
        schema_version: 1,
        algorithm: 'sha256',
        files,
    };
}

function checkRuntime(expected) {
    if (!existsSync(manifestPath)) {
        throw new Error(`runtime manifest missing: ${manifestPath}`);
    }
    const actual = JSON.parse(readFileSync(manifestPath, 'utf8'));
    if (JSON.stringify(actual) !== JSON.stringify(expected)) {
        throw new Error('runtime manifest is stale; run npm run sync-runtime');
    }
    for (const name of TOOLS) {
        const bundled = join(runtimeDir, name);
        if (!existsSync(bundled)) {
            throw new Error(`bundled runtime file missing: ${bundled}`);
        }
        if (sha256(bundled) !== expected.files[name]) {
            throw new Error(`bundled runtime drift detected: ${name}`);
        }
    }
}

try {
    const expected = expectedManifest();
    if (checkOnly) {
        checkRuntime(expected);
        process.stdout.write(`runtime bundle verified (${TOOLS.length} tools)\n`);
    } else {
        mkdirSync(runtimeDir, { recursive: true });
        for (const name of TOOLS) {
            copyFileSync(join(sourceDir, name), join(runtimeDir, name));
        }
        writeFileSync(manifestPath, `${JSON.stringify(expected, null, 2)}\n`, 'utf8');
        checkRuntime(expected);
        process.stdout.write(`runtime bundle synchronized (${TOOLS.length} tools)\n`);
    }
} catch (error) {
    process.stderr.write(`sync-runtime: ${error.message}\n`);
    process.exit(2);
}
