#!/usr/bin/env node
// skynet.js — the node dispatcher.
//
// When a user types `skynet` anywhere on PATH, npm's cmd-shim lands here.
// Our job is dumb and fast: find Python, spawn tools/skynet_repl.py with the
// right cwd + env, forward stdio + signals, propagate exit code. No business
// logic lives here — the REPL itself is the soul.
//
// Layout is resolved at runtime:
//   repoRoot      -> SKYNET_REPO_ROOT, repo-only config if present, then upward markers
//   replEntry     → tools/skynet_repl.py
//   updateEntry   → tools/skynet_update.py (called by tools/skynet_cli.py)
//   skillRegistry -> data/skynet_skill_registry.json
//   providerChain -> [gemini] permanently
//
// Args passed through to the REPL unchanged. Command-mode subcommands are
// routed to the canonical Python CLI; update/upgrade are handled there so the
// Skynet CLI upgrades itself through its own command surface.

'use strict';

const { spawn, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const PKG = require('../package.json');

function loadRepoConfig() {
    const configPath = path.resolve(__dirname, '..', 'repo-config.json');
    try {
        const value = JSON.parse(fs.readFileSync(configPath, 'utf8'));
        return value && typeof value === 'object' && !Array.isArray(value)
            ? value
            : {};
    } catch (_) {
        // The public package intentionally excludes repository-only metadata.
        return {};
    }
}

const CONFIG = loadRepoConfig();
const EX_CONFIG = 78;
const BUNDLED_COMMANDS = new Map([
    ['auth-status', 'skynet_provider_oauth.py'],
    ['release-gate', 'skynet_public_release_gate.py'],
    ['publish-gate', 'skynet_npm_publish_gate.py'],
    ['boundary-guard', 'skynet_publish_boundary_guard.py'],
]);

function printHelp() {
    process.stdout.write([
        `Skynet CLI v${PKG.version}`,
        '',
        'Usage:',
        '  skynet [command] [options]',
        '  skynet run "<task>"',
        '  skynet --version',
        '  skynet --help',
        '',
        'Standalone publish-safety commands (no repository required):',
        '  auth-status     Redacted Codex, Claude, and Antigravity OAuth inventory',
        '  release-gate    Scan a repository or path set before public release',
        '  publish-gate    Pack, scan, install, and smoke-test an npm package',
        '  boundary-guard  Enforce a declared public-surface boundary',
        '',
        'Requirements for bundled commands:',
        '  - Node.js 18 or newer',
        '  - Python 3.10 or newer',
        '',
        'Fleet and orchestration commands such as health, status, run, and the',
        'interactive console require the private repository-hosted runtime.',
        '',
        'Point the CLI at that checkout with SKYNET_REPO_ROOT:',
        '  Windows PowerShell: $env:SKYNET_REPO_ROOT = "$env:USERPROFILE\\Skynet-AI"',
        '  POSIX shell:        export SKYNET_REPO_ROOT="$HOME/Skynet-AI"',
        '',
        `Homepage: ${PKG.homepage}`,
    ].join('\n') + '\n');
}

function failMissingRepo() {
    process.stderr.write([
        'skynet: runtime not found; this command requires the repository-hosted runtime.',
        'The Python runtime lives in the private Skynet AI repository and is not bundled',
        'inside the npm package. Set SKYNET_REPO_ROOT to the repository checkout:',
        '  Windows PowerShell: $env:SKYNET_REPO_ROOT = "$env:USERPROFILE\\Skynet-AI"',
        '  POSIX shell:        export SKYNET_REPO_ROOT="$HOME/Skynet-AI"',
        `Homepage: ${PKG.homepage}`,
    ].join('\n') + '\n');
    process.exit(EX_CONFIG);
}

function failMissingPython() {
    process.stderr.write([
        'skynet: Python runtime not found; Python 3.10 or newer is required.',
        'Install Python 3.10+ or set SKYNET_PYTHON to a compatible interpreter:',
        '  Windows PowerShell: $env:SKYNET_PYTHON = "$env:LOCALAPPDATA\\Programs\\Python\\Python312\\python.exe"',
        '  POSIX shell:        export SKYNET_PYTHON="$(command -v python3)"',
        `Homepage: ${PKG.homepage}`,
    ].join('\n') + '\n');
    process.exit(EX_CONFIG);
}

function repoRoot() {
    if (process.env.SKYNET_REPO_ROOT && fs.existsSync(process.env.SKYNET_REPO_ROOT)) {
        return process.env.SKYNET_REPO_ROOT;
    }
    if (CONFIG.repoRoot && fs.existsSync(CONFIG.repoRoot)) {
        return CONFIG.repoRoot;
    }
    // Fallback: search upward from the package dir for a marker file.
    let dir = path.resolve(__dirname, '..');
    for (let i = 0; i < 6; i++) {
        if (fs.existsSync(path.join(dir, 'Skynet')) && fs.existsSync(path.join(dir, 'tools'))) {
            return dir;
        }
        const parent = path.dirname(dir);
        if (parent === dir) break;
        dir = parent;
    }
    return null;
}

function pythonCacheFile() {
    let root;
    if (process.platform === 'win32') {
        root = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
    } else if (process.platform === 'darwin') {
        root = path.join(os.homedir(), 'Library', 'Caches');
    } else {
        const xdg = process.env.XDG_CACHE_HOME;
        root = xdg && path.isAbsolute(xdg) ? xdg : path.join(os.homedir(), '.cache');
    }
    return path.join(root, 'skynet-cli', `python-${PKG.version}.json`);
}

function posixOwnedAndPrivate(stat) {
    if (process.platform === 'win32' || typeof process.getuid !== 'function') {
        return true;
    }
    return stat.uid === process.getuid() && (stat.mode & 0o022) === 0;
}

function readPythonCache(cacheFile) {
    let fd;
    try {
        const directoryStat = fs.statSync(path.dirname(cacheFile));
        if (!directoryStat.isDirectory() || !posixOwnedAndPrivate(directoryStat)) {
            return null;
        }
        const noFollow = process.platform === 'win32'
            ? 0
            : (fs.constants.O_NOFOLLOW || 0);
        fd = fs.openSync(cacheFile, fs.constants.O_RDONLY | noFollow);
        const cacheStat = fs.fstatSync(fd);
        if (!cacheStat.isFile() || !posixOwnedAndPrivate(cacheStat)) {
            return null;
        }
        const cached = JSON.parse(fs.readFileSync(fd, 'utf8'));
        if (
            !cached
            || cached.cliVersion !== PKG.version
            || typeof cached.pythonPath !== 'string'
            || !path.isAbsolute(cached.pythonPath)
        ) {
            return null;
        }
        return cached;
    } catch (_) {
        // Missing, corrupt, symlinked, foreign-owned, or unreadable cache:
        // rediscover instead of making cache state a CLI failure.
        return null;
    } finally {
        if (fd !== undefined) {
            try { fs.closeSync(fd); } catch (_) { /* best-effort close */ }
        }
    }
}

function writePythonCache(cacheFile, pythonPath) {
    const cacheDir = path.dirname(cacheFile);
    let temporary;
    try {
        fs.mkdirSync(cacheDir, { recursive: true, mode: 0o700 });
        const directoryStat = fs.statSync(cacheDir);
        if (!directoryStat.isDirectory() || !posixOwnedAndPrivate(directoryStat)) {
            return;
        }
        if (process.platform !== 'win32') {
            fs.chmodSync(cacheDir, 0o700);
        }
        temporary = path.join(
            cacheDir,
            `.python-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}.tmp`,
        );
        fs.writeFileSync(
            temporary,
            JSON.stringify({ pythonPath, cliVersion: PKG.version, ts: Date.now() }),
            { encoding: 'utf8', mode: 0o600, flag: 'wx' },
        );
        if (process.platform !== 'win32') {
            fs.chmodSync(temporary, 0o600);
        }
        try {
            fs.renameSync(temporary, cacheFile);
        } catch (error) {
            // Windows does not replace an existing destination atomically.
            // This directory is per-user; remove only this package-owned cache.
            if (process.platform !== 'win32') throw error;
            try { fs.unlinkSync(cacheFile); } catch (unlinkError) {
                if (unlinkError.code !== 'ENOENT') throw unlinkError;
            }
            fs.renameSync(temporary, cacheFile);
        }
        temporary = undefined;
    } catch (_) {
        // Cache persistence is an optimization, never a startup requirement.
    } finally {
        if (temporary !== undefined) {
            try { fs.unlinkSync(temporary); } catch (_) { /* best-effort cleanup */ }
        }
    }
}

// Resolve a candidate to its ABSOLUTE interpreter path (sys.executable) so the
// per-user cache never has to preserve an ambiguous PATH command name.
function resolveAbsPython(command) {
    const r = spawnSync(command, ['-c', 'import sys;print(sys.executable)'], {
        encoding: 'utf8', shell: false, windowsHide: true,
    });
    if (r.status === 0) {
        const abs = (r.stdout || '').trim();
        if (abs && fs.existsSync(abs)) return abs;
    }
    return command; // fall back to the name if abs resolution fails
}

function findPython() {
    if (process.env.SKYNET_PYTHON && fs.existsSync(process.env.SKYNET_PYTHON)) {
        return pythonUsable(process.env.SKYNET_PYTHON) ? process.env.SKYNET_PYTHON : null;
    }
    // Fast path trade-off: make one cheap `--version` spawn for a cached absolute
    // path. This is slightly slower than existsSync, but still avoids up to three
    // PATH candidate probes and detects replacement/downgrade before execution.
    const cacheFile = pythonCacheFile();
    const cached = readPythonCache(cacheFile);
    if (cached && pythonUsable(cached.pythonPath)) {
        return cached.pythonPath;
    }

    const candidates = process.platform === 'win32'
        ? ['python', 'python3', 'py']
        : ['python3', 'python'];
    for (const c of candidates) {
        if (pythonUsable(c)) {
            const abs = resolveAbsPython(c);
            writePythonCache(cacheFile, abs);
            return abs;
        }
    }
    return null;
}

function pythonUsable(command) {
    const r = spawnSync(command, ['--version'], {
        encoding: 'utf8',
        shell: false,
        windowsHide: true,
    });
    if (r.status !== 0) return false;
    const text = `${r.stdout || ''} ${r.stderr || ''}`;
    const match = text.match(/Python\s+(\d+)\.(\d+)\.(\d+)/i);
    if (!match) return false;
    const major = Number(match[1]);
    const minor = Number(match[2]);
    return major > 3 || (major === 3 && minor >= 10);
}

function fail(msg, code = 1) {
    process.stderr.write(`skynet: ${msg}\n`);
    process.exit(code);
}

function loadCliManifest(root) {
    const manifestPath = path.join(root, 'data', 'skynet_cli_manifest.json');
    try {
        return JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    } catch (_) {
        return null;
    }
}

function fallbackCliCommands() {
    return new Set([
        'start', 'restart', 'open', 'supervise', 'autostart',
        'dispatch', 'health', 'audit', 'decompose',
        'orchestrate-plan', 'orchestration-plan', 'plan-os', 'system-os-plan',
        'status', 'pipeline', 'metrics', 'bus',
        'platform-research', 'platform-deep-research', 'social-channels',
        'social-director', 'viral-director', 'viral-playbook',
        'codex-endless', 'codex-auto',
        'version', 'pulse', 'lanes', 'provider-lanes', 'chrome-status',
        'capabilities', 'command-center', 'control-center', 'complete',
        'origin', 'prompt', 'convene', 'doctor', 'truth', 'update', 'upgrade', 'self-upgrade',
        'commands', 'prophet',
        'skills', 'todo-memory', 'agent', 'opus5', 'claude-task', 'sol', 'sol-1', 'sol-2', 'accounts',
        'auth-status',
        'codex-model-probe',
        'mcp-server', 'apply', 'completion',
        'mcp',
        'ps', 'powershell', 'ps-invoke',
        'local-status', 'local-exec', 'local-dispatch',
        'claude-auth', 'claude-health', 'claude-prompt', 'codex-auth', 'gemini-auth', 'google-login',
        'antigravity-status', 'antigravity-fix', 'anti-status', 'anti-fix', 'antigravity-bridge',
        'vsix-health', 'vsix-status', 'vsix-prompt',
        'vsix-fleet-status', 'vsix-fleet-metrics',
        'remote',
    ]);
}

function fallbackLegacyCommands() {
    return new Set([
        'up', 'down', 'vsix', 'reload', 'claude-truth', 'publish', 'spawn', 'poke', 'inbox', 'watch',
    ]);
}

function manifestCommands(manifest) {
    const commands = new Set();
    for (const name of manifest?.commands?.canonical || []) {
        commands.add(name);
    }
    for (const name of manifest?.commands?.router_builtin || []) {
        commands.add(name);
    }
    return commands.size > 0 ? commands : fallbackCliCommands();
}

function manifestLegacyCommands(manifest) {
    const commands = new Set(manifest?.commands?.legacy_overseer_only || []);
    return commands.size > 0 ? commands : fallbackLegacyCommands();
}

function manifestLegacyPrefix(manifest) {
    return manifest?.routing?.force_legacy_prefix || 'overseer';
}

function manifestEntry(manifest, key, fallback) {
    const value = manifest?.entrypoints?.[key]?.path || fallback;
    if (typeof value !== 'string' || value.length === 0) {
        return fallback;
    }
    if (path.isAbsolute(value) || value.split(/[\\/]+/).includes('..')) {
        return fallback;
    }
    return value;
}

function spawnPython(py, entry, forwarded, options = {}) {
    const child = spawn(py, [entry, ...forwarded], {
        cwd: options.cwd || process.cwd(),
        env: options.env || process.env,
        stdio: 'inherit',
        shell: false,
    });

    child.on('exit', (code, signal) => {
        if (signal) {
            process.exit(128 + (os.constants.signals[signal] || 0));
        }
        process.exit(code ?? 0);
    });

    child.on('error', (err) => {
        fail(`failed to spawn Python: ${err.message}`);
    });
}

function main() {
    const args = process.argv.slice(2);
    if (args.length === 1 && (args[0] === '--version' || args[0] === '-v')) {
        process.stdout.write(`${PKG.version}\n`);
        process.exit(0);
    }
    if (args.length === 1 && (args[0] === '--help' || args[0] === '-h')) {
        printHelp();
        process.exit(0);
    }

    const bundledEntry = BUNDLED_COMMANDS.get(args[0]);
    if (bundledEntry) {
        const py = findPython();
        if (!py) {
            failMissingPython();
        }
        const entry = path.resolve(__dirname, '..', 'runtime', bundledEntry);
        if (!fs.existsSync(entry)) {
            fail(`bundled runtime entrypoint missing: ${bundledEntry}`, EX_CONFIG);
        }
        spawnPython(py, entry, args.slice(1));
        return;
    }

    const root = repoRoot();
    if (!root) {
        failMissingRepo();
    }

    const py = findPython();
    if (!py) {
        failMissingPython();
    }
    let runMode = false;
    if (args[0] === 'run') {
        runMode = true;
    }

    const manifest = loadCliManifest(root);
    const cliCommands = manifestCommands(manifest);
    const legacyCommands = manifestLegacyCommands(manifest);
    const legacyPrefix = manifestLegacyPrefix(manifest);
    const isLegacyCommand = !runMode && (legacyCommands.has(args[0]) || args[0] === legacyPrefix);
    const isCliCommand = !runMode && (cliCommands.has(args[0]) || isLegacyCommand);
    const entry = isCliCommand
        ? path.join(root, manifestEntry(manifest, 'local_router', 'tools/skynet_cli_router.py'))
        : path.join(root, manifestEntry(manifest, 'interactive_repl', CONFIG.replEntry || 'tools/skynet_repl.py'));

    if (!fs.existsSync(entry)) {
        fail(`entrypoint missing: ${entry}`);
    }

    const forwarded = runMode
        ? ['--plain', '--no-banner', '--quiet', '--no-footer', ...args.slice(1)]
        : args;

    const env = {
        ...process.env,
        PYTHONIOENCODING: 'utf-8',
        PYTHONUTF8: '1',
        SKYNET_REPO_ROOT: root,
        SKYNET_BUS_URL: process.env.SKYNET_BUS_URL || CONFIG.busUrl || 'http://localhost:8420',
        SKYNET_VSIX_URL: process.env.SKYNET_VSIX_URL || CONFIG.vsixUrl || 'http://localhost:8419',
        SKYNET_IDENTITY: process.env.SKYNET_IDENTITY || CONFIG.identity || 'Prophet',
        SKYNET_ROUTE_POLICY: 'truth-first',
        SKYNET_PROVIDER_CHAIN: 'gemini',
        SKYNET_CLI_MANIFEST: process.env.SKYNET_CLI_MANIFEST || path.join(root, 'data', 'skynet_cli_manifest.json'),
        SKYNET_SKILL_REGISTRY: process.env.SKYNET_SKILL_REGISTRY || path.join(root, manifest?.skill_registry?.path || CONFIG.skillRegistry || 'data/skynet_skill_registry.json'),
        SKYNET_DEFAULT_MODEL: 'gemini-3.1-pro-preview',
        SKYNET_DEFAULT_CODEX_MODEL: process.env.SKYNET_DEFAULT_CODEX_MODEL || 'gpt-5.6-sol',
        SKYNET_CODEX_MODEL: process.env.SKYNET_CODEX_MODEL || 'gpt-5.6-sol',
        // Operational routing is Gemini-only, but the Claude default is the
        // advisor lane's family — a Gemini id here is a landmine (Claude cannot
        // run a gemini model). Keep it a real Claude alias. No source reads this
        // today; setting it correctly avoids breaking a future consumer.
        SKYNET_DEFAULT_CLAUDE_MODEL: 'opus[1m]',
        SKYNET_CLI_VERSION: PKG.version,
    };

    spawnPython(py, entry, forwarded, { cwd: root, env });
}

if (require.main === module) {
    main();
} else {
    module.exports = {
        findPython,
        loadRepoConfig,
        pythonCacheFile,
        pythonUsable,
        repoRoot,
    };
}
