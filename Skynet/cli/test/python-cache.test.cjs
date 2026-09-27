'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const cliPath = path.resolve(__dirname, '..', 'bin', 'skynet.js');
const packageJson = require('../package.json');
const originalSpawnSync = childProcess.spawnSync;
let spawnImpl = () => ({ status: 1, stdout: '', stderr: '' });

childProcess.spawnSync = (...args) => spawnImpl(...args);
delete require.cache[require.resolve(cliPath)];
const cli = require(cliPath);
childProcess.spawnSync = originalSpawnSync;

function result(status, stdout = '', stderr = '') {
    return { status, stdout, stderr };
}

function writeExisting(file, contents = '') {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, contents, 'utf8');
    return file;
}

function withCacheEnv(root, action) {
    const names = ['LOCALAPPDATA', 'XDG_CACHE_HOME', 'SKYNET_PYTHON'];
    const before = Object.fromEntries(names.map((name) => [name, process.env[name]]));
    process.env.LOCALAPPDATA = root;
    process.env.XDG_CACHE_HOME = root;
    delete process.env.SKYNET_PYTHON;
    try {
        return action();
    } finally {
        for (const name of names) {
            if (before[name] === undefined) delete process.env[name];
            else process.env[name] = before[name];
        }
    }
}

test('hostile shared-temp cache is never trusted', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'skynet-cache-test-'));
    const attacker = writeExisting(path.join(root, 'attacker-binary'));
    const legitimate = writeExisting(path.join(root, 'legitimate-python'));
    const hostileCache = path.join(
        os.tmpdir(),
        `skynet-python-${packageJson.version}.json`,
    );
    let originalCache;
    try {
        try { originalCache = fs.readFileSync(hostileCache); } catch (_) { /* absent */ }
        fs.writeFileSync(
            hostileCache,
            JSON.stringify({ pythonPath: attacker, cliVersion: packageJson.version }),
            'utf8',
        );
        spawnImpl = (_command, args) => {
            if (args[0] === '--version') return result(0, 'Python 3.12.4\n');
            if (args[0] === '-c') return result(0, `${legitimate}\n`);
            return result(1);
        };

        const found = withCacheEnv(root, () => cli.findPython());

        assert.equal(found, legitimate);
        assert.notEqual(cli.pythonCacheFile(), hostileCache);
    } finally {
        if (originalCache === undefined) {
            try { fs.unlinkSync(hostileCache); } catch (_) { /* absent */ }
        } else {
            fs.writeFileSync(hostileCache, originalCache);
        }
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test('cached interpreter is rejected after downgrade below Python 3.10', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'skynet-cache-test-'));
    const interpreter = writeExisting(path.join(root, 'python-runtime'));
    let phase = 'discover';
    try {
        spawnImpl = (command, args) => {
            if (phase === 'discover' && args[0] === '--version') {
                return result(0, 'Python 3.12.4\n');
            }
            if (phase === 'discover' && args[0] === '-c') {
                return result(0, `${interpreter}\n`);
            }
            if (phase === 'downgraded' && command === interpreter && args[0] === '--version') {
                return result(0, 'Python 3.9.19\n');
            }
            return result(1);
        };

        withCacheEnv(root, () => {
            assert.equal(cli.findPython(), interpreter);
            phase = 'downgraded';
            assert.equal(cli.findPython(), null);
        });
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test('corrupt cache is ignored and discovery continues without throwing', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'skynet-cache-test-'));
    const interpreter = writeExisting(path.join(root, 'python-runtime'));
    try {
        withCacheEnv(root, () => {
            const cacheFile = cli.pythonCacheFile();
            writeExisting(cacheFile, '{"pythonPath":');
            spawnImpl = (_command, args) => {
                if (args[0] === '--version') return result(0, 'Python 3.11.9\n');
                if (args[0] === '-c') return result(0, `${interpreter}\n`);
                return result(1);
            };

            assert.doesNotThrow(() => cli.findPython());
            assert.equal(cli.findPython(), interpreter);
        });
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test('SKYNET_PYTHON is validated first and wins over cache and PATH', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'skynet-cache-test-'));
    const selected = writeExisting(path.join(root, 'selected-python'));
    const calls = [];
    try {
        withCacheEnv(root, () => {
            process.env.SKYNET_PYTHON = selected;
            spawnImpl = (command, args) => {
                calls.push([command, ...args]);
                return command === selected && args[0] === '--version'
                    ? result(0, 'Python 3.10.14\n')
                    : result(1);
            };

            assert.equal(cli.findPython(), selected);
            assert.deepEqual(calls, [[selected, '--version']]);
        });
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test(
    'group/other-writable POSIX cache is ignored',
    { skip: process.platform === 'win32' },
    () => {
        const root = fs.mkdtempSync(path.join(os.tmpdir(), 'skynet-cache-test-'));
        const attacker = writeExisting(path.join(root, 'attacker-binary'));
        const legitimate = writeExisting(path.join(root, 'legitimate-python'));
        try {
            withCacheEnv(root, () => {
                const cacheFile = cli.pythonCacheFile();
                writeExisting(
                    cacheFile,
                    JSON.stringify({
                        pythonPath: attacker,
                        cliVersion: packageJson.version,
                    }),
                );
                fs.chmodSync(cacheFile, 0o666);
                spawnImpl = (_command, args) => {
                    if (args[0] === '--version') return result(0, 'Python 3.12.4\n');
                    if (args[0] === '-c') return result(0, `${legitimate}\n`);
                    return result(1);
                };

                assert.equal(cli.findPython(), legitimate);
            });
        } finally {
            fs.rmSync(root, { recursive: true, force: true });
        }
    },
);
