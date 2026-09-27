'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const packageRoot = path.resolve(__dirname, '..');
const cliPath = path.join(packageRoot, 'bin', 'skynet.js');
const unsupportedKeywords = new Set([
    'ai',
    'gemini',
    'fleet',
    'orchestration',
    'system-os',
    'repl',
]);

function packAndExtract() {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'skynet-pack-test-'));
    const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
    const packed = childProcess.spawnSync(
        npm,
        [
            'pack',
            '--json',
            '--ignore-scripts',
            '--pack-destination',
            root,
        ],
        {
            cwd: packageRoot,
            encoding: 'utf8',
            shell: process.platform === 'win32',
        },
    );
    assert.equal(
        packed.status,
        0,
        `npm pack failed\nstdout:\n${packed.stdout}\nstderr:\n${packed.stderr}`,
    );
    const result = JSON.parse(packed.stdout);
    assert.equal(result.length, 1);
    const extracted = childProcess.spawnSync(
        'tar',
        ['-xzf', result[0].filename],
        { cwd: root, encoding: 'utf8' },
    );
    assert.equal(
        extracted.status,
        0,
        `tar extraction failed\nstdout:\n${extracted.stdout}\nstderr:\n${extracted.stderr}`,
    );
    return { root, packageDir: path.join(root, 'package'), packResult: result[0] };
}

test('published package metadata describes only bundled publish-safety commands', () => {
    const packed = packAndExtract();
    try {
        const packageJsonPath = path.join(packed.packageDir, 'package.json');
        const raw = fs.readFileSync(packageJsonPath, 'utf8');
        const metadata = JSON.parse(raw);
        const lower = raw.toLowerCase();

        // Pin the packed version to the SOURCE manifest, never to a literal:
        // a hard-coded version turns every routine bump into a red test.
        const sourceVersion = JSON.parse(
            fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'),
        ).version;
        assert.equal(metadata.version, sourceVersion);
        assert.equal(Object.hasOwn(metadata, 'skynet'), false);
        assert.equal(lower.includes('localhost'), false);
        assert.equal(lower.includes('tools/skynet_cli.py'), false);
        assert.equal(lower.includes('modelfloor'), false);
        assert.equal(lower.includes('"forbidden"'), false);
        assert.deepEqual(
            metadata.keywords.filter((word) => unsupportedKeywords.has(word)),
            [],
        );
        assert.equal(
            packed.packResult.files.some(
                (entry) => entry.path.replaceAll('\\', '/') === 'repo-config.json',
            ),
            false,
        );
    } finally {
        fs.rmSync(packed.root, { recursive: true, force: true });
    }
});

test('repo mode resolves the excluded repository config', () => {
    const cli = require(cliPath);
    const config = cli.loadRepoConfig();
    const originalRoot = process.env.SKYNET_REPO_ROOT;
    try {
        process.env.SKYNET_REPO_ROOT = path.resolve(packageRoot, '..', '..');
        assert.equal(cli.repoRoot(), process.env.SKYNET_REPO_ROOT);
    } finally {
        if (originalRoot === undefined) delete process.env.SKYNET_REPO_ROOT;
        else process.env.SKYNET_REPO_ROOT = originalRoot;
    }

    assert.equal(config.cliEntry, 'tools/skynet_cli.py');
    assert.equal(config.replEntry, 'tools/skynet_repl.py');
    assert.equal(config.skillRegistry, 'data/skynet_skill_registry.json');
    assert.equal(config.busUrl, 'http://localhost:8420');
    assert.equal(config.vsixUrl, 'http://localhost:8419');
    assert.equal(config.identity, 'Prophet');
    assert.equal(config.defaultModel, 'gemini-3.1-pro-preview');
});
