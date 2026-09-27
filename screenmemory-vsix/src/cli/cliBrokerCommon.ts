// Shared broker constants/helpers for the ScreenMemory CLI routing layer.

import * as os from 'node:os';
import * as path from 'node:path';

export const BROKER_SECRET_HEADER = 'x-screenmemory-broker-secret';
export const BROKER_WORKSPACE_HEADER = 'x-screenmemory-workspace';
export const BROKER_HEARTBEAT_MS = 3000;
export const BROKER_STALE_MS = 15000;
export const BROKER_IDLE_EXIT_MS = 5 * 60 * 1000; // 5 minutes — gives VS Code plenty of time to reload + re-register

export interface BrokerRegistrationBody {
    backendId: string;
    port: number;
    processId: number;
    workspaceRoots?: string[];
    provider?: string;
    model?: string;
    windowTitle?: string;
}

export function getBrokerStateDir(): string {
    const base = process.env.LOCALAPPDATA
        || path.join(os.homedir(), 'AppData', 'Local');
    return path.join(base, 'ScreenMemory', 'cli-broker');
}

export function getBrokerSecretPath(): string {
    return path.join(getBrokerStateDir(), 'broker.secret');
}

export function normalizeWorkspacePath(value: string | undefined | null): string | null {
    const raw = String(value ?? '').trim();
    if (!raw) {
        return null;
    }

    let normalized = raw;
    if (raw.startsWith('file://')) {
        try {
            normalized = new URL(raw).pathname;
        } catch {
            // Keep the raw value if URL parsing fails.
        }
    }
    normalized = normalized.replace(/\//g, path.sep).replace(/[\\\/]+$/, '');

    if (process.platform === 'win32') {
        normalized = normalized.toLowerCase();
    }
    return normalized || null;
}

export function uniqueNormalizedWorkspaces(values: readonly string[] | undefined | null): string[] {
    const seen = new Set<string>();
    const ordered: string[] = [];
    for (const value of values ?? []) {
        const normalized = normalizeWorkspacePath(value);
        if (!normalized || seen.has(normalized)) {
            continue;
        }
        seen.add(normalized);
        ordered.push(normalized);
    }
    return ordered;
}
