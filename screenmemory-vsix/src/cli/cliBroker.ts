// Detached CLI broker that owns port 8419 and routes requests to live VSIX backends.
// signed: copilot

import * as crypto from 'node:crypto';
import * as fs from 'node:fs/promises';
import * as http from 'node:http';
import * as path from 'node:path';
import {
    BROKER_HEARTBEAT_MS,
    BROKER_IDLE_EXIT_MS,
    BROKER_SECRET_HEADER,
    BROKER_STALE_MS,
    BROKER_WORKSPACE_HEADER,
    getBrokerSecretPath,
    getBrokerStateDir,
    normalizeWorkspacePath,
    uniqueNormalizedWorkspaces,
    type BrokerRegistrationBody,
} from './cliBrokerCommon';

interface RegisteredBackend extends BrokerRegistrationBody {
    workspaceRoots: string[];
    registeredAt: number;
    lastSeen: number;
}

interface RouteSelection {
    backend: RegisteredBackend | null;
    status: number;
    error?: string;
    requestedWorkspace?: string | null;
}

class CliBroker {
    private readonly backends = new Map<string, RegisteredBackend>();
    private server: http.Server | null = null;
    private readonly secret = crypto.randomBytes(32).toString('hex');
    private pruneTimer: ReturnType<typeof setInterval> | null = null;
    private idleExitTimer: ReturnType<typeof setTimeout> | null = null;
    private leaderBackendId: string | null = null;

    constructor(private readonly port: number) {}

    async start(): Promise<void> {
        await fs.mkdir(getBrokerStateDir(), { recursive: true });

        await new Promise<void>((resolve, reject) => {
            this.server = http.createServer((req, res) => {
                void this.handleRequest(req, res);
            });
            this.server.once('error', (err: NodeJS.ErrnoException) => {
                if (err.code === 'EADDRINUSE') {
                    this.log(`Port ${this.port} already owned; exiting broker candidate`);
                    process.exit(0);
                    return;
                }
                reject(err);
            });
            this.server.once('listening', () => {
                void fs.writeFile(getBrokerSecretPath(), `${this.secret}\n`, 'utf-8')
                    .then(() => resolve())
                    .catch(reject);
            });
            this.server.listen(this.port);
        });

        this.pruneTimer = setInterval(() => {
            this.pruneStaleBackends();
        }, BROKER_HEARTBEAT_MS);
        this.log(`CLI broker listening on http://localhost:${this.port}`);
    }

    private async handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
        const origin = req.headers.origin ?? '';
        const isLocalOrigin = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin);
        res.setHeader('Access-Control-Allow-Origin', isLocalOrigin ? origin : 'http://localhost');
        res.setHeader('Vary', 'Origin');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', `Content-Type, ${BROKER_WORKSPACE_HEADER}`);

        if (req.method === 'OPTIONS') {
            res.writeHead(204);
            res.end();
            return;
        }

        this.pruneStaleBackends();
        const url = new URL(req.url ?? '/', 'http://127.0.0.1');
        const pathname = url.pathname;

        if (req.method === 'GET' && pathname === '/health') {
            this.sendJson(res, 200, {
                ok: true,
                broker: true,
                port: this.port,
                backendCount: this.backends.size,
                leaderBackendId: this.resolveLeaderBackend()?.backendId ?? null,
                workspaces: this.listWorkspaces(),
            });
            return;
        }

        if (req.method === 'GET' && pathname === '/backends') {
            this.sendJson(res, 200, {
                ok: true,
                broker: true,
                leaderBackendId: this.resolveLeaderBackend()?.backendId ?? null,
                backends: [...this.backends.values()].map(backend => ({
                    backendId: backend.backendId,
                    port: backend.port,
                    processId: backend.processId,
                    workspaceRoots: backend.workspaceRoots,
                    provider: backend.provider ?? null,
                    model: backend.model ?? null,
                    windowTitle: backend.windowTitle ?? null,
                    registeredAt: backend.registeredAt,
                    lastSeen: backend.lastSeen,
                })),
            });
            return;
        }

        const rawBody = await this.readRawBody(req);
        const parsedBody = this.parseJson(rawBody);

        if (req.method === 'POST' && pathname === '/register') {
            if (!this.hasValidSecret(req)) {
                this.sendJson(res, 401, { error: 'Invalid broker secret' });
                return;
            }
            await this.handleRegister(res, parsedBody);
            return;
        }

        if (req.method === 'POST' && pathname === '/unregister') {
            if (!this.hasValidSecret(req)) {
                this.sendJson(res, 401, { error: 'Invalid broker secret' });
                return;
            }
            await this.handleUnregister(res, parsedBody);
            return;
        }

        await this.proxyToBackend(req, res, url, rawBody, parsedBody);
    }

    private async handleRegister(res: http.ServerResponse, body: unknown): Promise<void> {
        const payload = body as Partial<BrokerRegistrationBody> | null;
        const backendId = payload?.backendId?.trim();
        const port = Number(payload?.port);
        const processId = Number(payload?.processId);
        if (!backendId || !Number.isFinite(port) || port <= 0 || !Number.isFinite(processId) || processId <= 0) {
            this.sendJson(res, 400, { error: 'Invalid backend registration payload' });
            return;
        }

        const existing = this.backends.get(backendId);
        const backend: RegisteredBackend = {
            backendId,
            port,
            processId,
            workspaceRoots: uniqueNormalizedWorkspaces(payload?.workspaceRoots),
            provider: payload?.provider?.trim() || undefined,
            model: payload?.model?.trim() || undefined,
            windowTitle: payload?.windowTitle?.trim() || undefined,
            registeredAt: existing?.registeredAt ?? Date.now(),
            lastSeen: Date.now(),
        };
        this.backends.set(backendId, backend);
        if (!this.leaderBackendId || !this.backends.has(this.leaderBackendId)) {
            this.leaderBackendId = this.pickLeaderBackendId();
        }
        this.cancelIdleExit();
        this.sendJson(res, 200, {
            ok: true,
            leaderBackendId: this.resolveLeaderBackend()?.backendId ?? backend.backendId,
            backendCount: this.backends.size,
        });
    }

    private async handleUnregister(res: http.ServerResponse, body: unknown): Promise<void> {
        const payload = body as { backendId?: string } | null;
        const backendId = payload?.backendId?.trim();
        if (!backendId) {
            this.sendJson(res, 400, { error: 'Missing backendId' });
            return;
        }

        this.backends.delete(backendId);
        if (this.leaderBackendId === backendId) {
            this.leaderBackendId = this.pickLeaderBackendId();
        }
        if (this.backends.size === 0) {
            this.scheduleIdleExit();
        }
        this.sendJson(res, 200, {
            ok: true,
            backendCount: this.backends.size,
            leaderBackendId: this.resolveLeaderBackend()?.backendId ?? null,
        });
    }

    private async proxyToBackend(
        req: http.IncomingMessage,
        res: http.ServerResponse,
        url: URL,
        rawBody: Buffer,
        parsedBody: unknown,
    ): Promise<void> {
        const selection = this.selectBackend(url.pathname, url, req, parsedBody);
        if (!selection.backend) {
            this.sendJson(res, selection.status, {
                error: selection.error ?? 'No backend available',
                requestedWorkspace: selection.requestedWorkspace ?? null,
                workspaces: this.listWorkspaces(),
                leaderBackendId: this.resolveLeaderBackend()?.backendId ?? null,
            });
            return;
        }

        const target = selection.backend;
        const headers: Record<string, string | string[] | undefined> = { ...req.headers };
        delete headers.host;
        delete headers[BROKER_SECRET_HEADER];
        headers.host = `127.0.0.1:${target.port}`;
        if (rawBody.length) {
            headers['content-length'] = String(rawBody.length);
        } else {
            delete headers['content-length'];
        }

        const upstream = http.request({
            hostname: '127.0.0.1',
            port: target.port,
            path: `${url.pathname}${url.search}`,
            method: req.method,
            headers,
        }, (upstreamRes) => {
            res.writeHead(upstreamRes.statusCode ?? 502, upstreamRes.headers);
            upstreamRes.pipe(res);
        });

        const abortUpstream = (): void => {
            if (!upstream.destroyed) {
                upstream.destroy();
            }
        };
        req.on('close', abortUpstream);
        res.on('close', abortUpstream);
        upstream.on('error', (err) => {
            if (!res.headersSent) {
                this.sendJson(res, 502, {
                    error: `Backend ${target.backendId} proxy failed: ${err.message}`,
                });
            } else {
                res.destroy(err);
            }
        });
        if (rawBody.length) {
            upstream.write(rawBody);
        }
        upstream.end();
    }

    private selectBackend(
        pathname: string,
        url: URL,
        req: http.IncomingMessage,
        parsedBody: unknown,
    ): RouteSelection {
        const requestedWorkspace = this.getRequestedWorkspace(url, req, parsedBody);
        const liveBackends = this.getLiveBackends();
        if (liveBackends.length === 0) {
            return {
                backend: null,
                status: 503,
                error: 'No live VSIX backends are registered',
                requestedWorkspace,
            };
        }

        if (requestedWorkspace) {
            const matches = this.rankBackendsByWorkspace(liveBackends, requestedWorkspace);
            if (matches.length === 0) {
                return {
                    backend: null,
                    status: 404,
                    error: `No VSIX backend matched workspace "${requestedWorkspace}"`,
                    requestedWorkspace,
                };
            }
            if (matches.length > 1 && matches[0].score === matches[1].score) {
                // Multiple backends share the same workspace (e.g. multiple VS Code windows open on the
                // same folder). Prefer the global leader; fall back to the earliest-registered backend
                // in the tied group rather than returning a 409 error. // signed: copilot
                const tiedBackends = matches.filter(m => m.score === matches[0].score).map(m => m.backend);
                const tieLeader = this.resolveLeaderBackend(tiedBackends);
                if (tieLeader) {
                    return { backend: tieLeader, status: 200, requestedWorkspace };
                }
                // resolveLeaderBackend returned nothing (shouldn't happen) — use earliest registered
                return { backend: matches[0].backend, status: 200, requestedWorkspace };
            }
            return {
                backend: matches[0].backend,
                status: 200,
                requestedWorkspace,
            };
        }

        const leader = this.resolveLeaderBackend(liveBackends);
        if (leader) {
            return { backend: leader, status: 200, requestedWorkspace: null };
        }

        const fallback = [...liveBackends].sort((a, b) => b.lastSeen - a.lastSeen)[0];
        return { backend: fallback, status: 200, requestedWorkspace: null };
    }

    private getRequestedWorkspace(url: URL, req: http.IncomingMessage, parsedBody: unknown): string | null {
        const header = req.headers[BROKER_WORKSPACE_HEADER];
        const headerValue = Array.isArray(header) ? header[0] : header;
        const bodyWorkspace = (
            parsedBody
            && typeof parsedBody === 'object'
            && 'workspace' in parsedBody
            && typeof (parsedBody as Record<string, unknown>).workspace === 'string'
        )
            ? String((parsedBody as Record<string, unknown>).workspace)
            : undefined;
        return normalizeWorkspacePath(
            url.searchParams.get('workspace')
            || headerValue
            || bodyWorkspace,
        );
    }

    private rankBackendsByWorkspace(
        backends: RegisteredBackend[],
        requestedWorkspace: string,
    ): Array<{ backend: RegisteredBackend; score: number }> {
        const ranked: Array<{ backend: RegisteredBackend; score: number }> = [];
        for (const backend of backends) {
            const score = backend.workspaceRoots.reduce((best, root) => {
                return Math.max(best, this.workspaceMatchScore(root, requestedWorkspace));
            }, 0);
            if (score > 0) {
                ranked.push({ backend, score });
            }
        }
        ranked.sort((a, b) => {
            if (b.score !== a.score) {
                return b.score - a.score;
            }
            if (a.backend.registeredAt !== b.backend.registeredAt) {
                return a.backend.registeredAt - b.backend.registeredAt;
            }
            return (a.backend?.backendId ?? '').localeCompare(b.backend?.backendId ?? '');
        });
        return ranked;
    }

    private workspaceMatchScore(root: string, requestedWorkspace: string): number {
        if (root === requestedWorkspace) {
            return 100_000 + root.length;
        }
        const withSep = `${root}${path.sep}`;
        if (requestedWorkspace.startsWith(withSep)) {
            return 1_000 + root.length;
        }
        return 0;
    }

    private hasValidSecret(req: http.IncomingMessage): boolean {
        const header = req.headers[BROKER_SECRET_HEADER];
        const token = Array.isArray(header) ? header[0] : header;
        return typeof token === 'string' && token === this.secret;
    }

    private async readRawBody(req: http.IncomingMessage): Promise<Buffer> {
        const maxBodySize = 1_048_576;
        return new Promise((resolve) => {
            const chunks: Buffer[] = [];
            let totalSize = 0;
            req.on('data', (chunk: Buffer) => {
                totalSize += chunk.length;
                if (totalSize > maxBodySize) {
                    req.destroy();
                    resolve(Buffer.alloc(0));
                    return;
                }
                chunks.push(chunk);
            });
            req.on('end', () => resolve(Buffer.concat(chunks)));
            req.on('error', () => resolve(Buffer.alloc(0)));
        });
    }

    private parseJson(rawBody: Buffer): unknown {
        if (!rawBody.length) {
            return null;
        }
        try {
            return JSON.parse(rawBody.toString('utf-8'));
        } catch {
            return null;
        }
    }

    private getLiveBackends(): RegisteredBackend[] {
        this.pruneStaleBackends();
        return [...this.backends.values()];
    }

    private pruneStaleBackends(): void {
        const now = Date.now();
        for (const [backendId, backend] of this.backends.entries()) {
            if (now - backend.lastSeen > BROKER_STALE_MS) {
                this.backends.delete(backendId);
            }
        }
        if (this.leaderBackendId && !this.backends.has(this.leaderBackendId)) {
            this.leaderBackendId = this.pickLeaderBackendId();
        }
        if (this.backends.size === 0) {
            this.scheduleIdleExit();
        }
    }

    private resolveLeaderBackend(backends?: RegisteredBackend[]): RegisteredBackend | null {
        const pool = backends ?? this.getLiveBackends();
        if (pool.length === 0) {
            return null;
        }
        if (this.leaderBackendId) {
            const current = pool.find(backend => backend.backendId === this.leaderBackendId);
            if (current) {
                return current;
            }
        }
        this.leaderBackendId = this.pickLeaderBackendId(pool);
        return this.leaderBackendId
            ? pool.find(backend => backend.backendId === this.leaderBackendId) ?? null
            : null;
    }

    private pickLeaderBackendId(backends?: RegisteredBackend[]): string | null {
        const pool = [...(backends ?? this.backends.values())];
        if (pool.length === 0) {
            return null;
        }
        pool.sort((a, b) => {
            const aHasWorkspace = a.workspaceRoots.length > 0 ? 1 : 0;
            const bHasWorkspace = b.workspaceRoots.length > 0 ? 1 : 0;
            if (aHasWorkspace !== bHasWorkspace) {
                return bHasWorkspace - aHasWorkspace;
            }
            if (a.registeredAt !== b.registeredAt) {
                return a.registeredAt - b.registeredAt;
            }
            return (a?.backendId ?? '').localeCompare(b?.backendId ?? '');
        });
        return pool[0].backendId;
    }

    private listWorkspaces(): string[] {
        const all = this.getLiveBackends().flatMap(backend => backend.workspaceRoots);
        return uniqueNormalizedWorkspaces(all);
    }

    private scheduleIdleExit(): void {
        if (this.idleExitTimer) {
            return;
        }
        this.idleExitTimer = setTimeout(() => {
            this.pruneStaleBackends();
            if (this.backends.size === 0) {
                void this.shutdown(0);
            } else {
                this.cancelIdleExit();
            }
        }, BROKER_IDLE_EXIT_MS);
    }

    private cancelIdleExit(): void {
        if (this.idleExitTimer) {
            clearTimeout(this.idleExitTimer);
            this.idleExitTimer = null;
        }
    }

    private async shutdown(exitCode: number): Promise<void> {
        this.cancelIdleExit();
        if (this.pruneTimer) {
            clearInterval(this.pruneTimer);
            this.pruneTimer = null;
        }
        await fs.unlink(getBrokerSecretPath()).catch(() => undefined);
        if (!this.server) {
            process.exit(exitCode);
            return;
        }
        this.server.close(() => process.exit(exitCode));
    }

    private sendJson(res: http.ServerResponse, status: number, data: unknown): void {
        const payload = JSON.stringify(data);
        res.writeHead(status, { 'Content-Type': 'application/json' });
        res.end(payload);
    }

    private log(message: string): void {
        const stamp = new Date().toISOString();
        console.error(`[CLI BROKER ${stamp}] ${message}`);
    }
}

function parsePort(argv: string[]): number {
    const idx = argv.findIndex(arg => arg === '--port');
    if (idx >= 0 && argv[idx + 1]) {
        const parsed = Number(argv[idx + 1]);
        if (Number.isFinite(parsed) && parsed > 0) {
            return parsed;
        }
    }
    return 8419;
}

async function main(): Promise<void> {
    const broker = new CliBroker(parsePort(process.argv.slice(2)));
    await broker.start();
}

void main().catch((err) => {
    console.error(`[CLI BROKER FATAL] ${err instanceof Error ? err.stack ?? err.message : String(err)}`);
    process.exit(1);
});
