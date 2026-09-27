// ScreenMemory VSIX - Gemini CDP provider
// Routes Gemini web UI through Chrome DevTools Protocol and exposes it through
// the same provider/tool-call contract used by native Skynet workers.
// signed: codex

import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import type {
    ModelInfo,
    CompletionRequest,
    CompletionResponse,
    StreamingChunk,
    AIProvider,
    ToolCall,
    ToolDefinition,
    ChatMessage,
} from '../types';
import {
    AIProviderBase,
    createStreamingResponse,
} from './providerBase';

const DEFAULT_CDP_PORT = 9226;
const DEFAULT_GEMINI_URL = 'https://gemini.google.com/app';
const DEFAULT_STABLE_MS = 4500;
const POLL_MS = 1000;
const CDP_CALL_TIMEOUT_MS = 30_000;
const MAX_RESPONSE_CHARS = 600_000;

// Compatibility route ID is retained so existing VSIX state keeps resolving;
// the browser path below fail-closes unless Gemini 3.6 Thinking is visibly selected.
const GEMINI_CDP_MODEL_ID = 'gemini-3.6-thinking';
const GEMINI_CDP_VIDEO_MODEL_ID = 'gemini-3.1-pro-video';
const VIDEO_EXTENSIONS = new Set(['.mp4', '.webm', '.mov', '.m4v']);

const GEMINI_CDP_MODELS: ModelInfo[] = [
    {
        id: GEMINI_CDP_MODEL_ID,
        name: 'Gemini 3.6 Thinking (CDP app)',
        provider: 'gemini-cdp' as AIProvider,
        contextWindow: 1000000,
        maxOutput: 65536,
        supportsStreaming: true,
        supportsTools: true,
        supportsVision: false,
    },
    {
        id: GEMINI_CDP_VIDEO_MODEL_ID,
        name: 'Gemini 3.1 Pro Videos (CDP app)',
        provider: 'gemini-cdp' as AIProvider,
        contextWindow: 1000000,
        maxOutput: 65536,
        supportsStreaming: true,
        supportsTools: true,
        supportsVision: false,
    },
];

type GeminiCdpTargetMode = 'background' | 'reuse-existing' | 'new-tab';

interface GeminiCdpOptions {
    port?: number;
    appUrl?: string;
    responseTimeoutMs?: number;
    closeTabAfterRequest?: boolean;
    stableMs?: number;
    targetMode?: GeminiCdpTargetMode;
    autoDownloadVideos?: boolean;
    mediaOptIn?: boolean;
    videoDownloadDir?: string;
}

interface CdpTarget {
    id: string;
    type: string;
    title?: string;
    url?: string;
    webSocketDebuggerUrl?: string;
    owned?: boolean;
    hidden?: boolean;
    ownerConnection?: CdpConnection;
}

interface CdpResponse<T = unknown> {
    id?: number;
    result?: T;
    error?: { code: number; message: string; data?: string };
}

interface RuntimeEvaluateResult {
    result?: {
        type?: string;
        value?: unknown;
        description?: string;
    };
    exceptionDetails?: unknown;
}

interface ComposerInfo {
    found: boolean;
    selector?: string;
    x?: number;
    y?: number;
    error?: string;
}

interface ModelSelectionInfo {
    selected: boolean;
    current?: string;
    error?: string;
    available?: string[];
}

interface ResponseState {
    active: boolean;
    promptFound: boolean;
    responseCount: number;
    hasNewResponse: boolean;
    text: string;
}

interface VideoAppSelectionInfo {
    selected: boolean;
    error?: string;
    available?: string[];
}

interface VideoState {
    hasVideo: boolean;
    duration?: number;
    currentTime?: number;
    source?: string;
    downloadable: boolean;
    text?: string;
}

interface ParsedProviderResponse {
    content: string;
    toolCalls: ToolCall[];
}

const COMPOSER_FOCUS_JS = String.raw`
(function(){
  const candidates = [
    'rich-textarea div[contenteditable="true"][role="textbox"]',
    'rich-textarea div[contenteditable="true"]',
    'div[contenteditable="true"][role="textbox"]',
    'div[contenteditable="true"][aria-label*="Enter a prompt" i]',
    'div[contenteditable="true"]',
    'textarea'
  ];
  for (const selector of candidates) {
    const el = document.querySelector(selector);
    if (!el) continue;
    const rect = el.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0) continue;
    try { el.focus(); el.click(); } catch (_) {}
    return JSON.stringify({
      found: true,
      selector,
      x: Math.round(rect.left + rect.width / 2),
      y: Math.round(rect.top + rect.height / 2)
    });
  }
  return JSON.stringify({
    found: false,
    error: 'composer_not_found',
    bodyText: (document.body.innerText || '').slice(0, 1000)
  });
})()
`;

const NEW_CHAT_CLICK_JS = String.raw`
(function(){
  function visible(el) {
    const rect = el.getBoundingClientRect();
    const style = window.getComputedStyle(el);
    return rect.width > 2 && rect.height > 2 &&
      style.visibility !== 'hidden' && style.display !== 'none' &&
      Number(style.opacity || '1') > 0.05;
  }
  for (const el of document.querySelectorAll('button, a, [role="button"]')) {
    const label = ((el.innerText || el.textContent || '') + ' ' +
      (el.getAttribute('aria-label') || '') + ' ' +
      (el.getAttribute('title') || '')).replace(/\s+/g, ' ').trim();
    if (/^new chat$/i.test(label) || /\bnew chat\b/i.test(label)) {
      if (!visible(el)) continue;
      try { el.click(); return true; } catch (_) {}
    }
  }
  return false;
})()
`;

const SELECT_PRO_MODEL_JS = String.raw`
(async () => {
  const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
  const textOf = (el) => (el?.innerText || el?.textContent || '').trim().replace(/\s+/g, ' ');
  const visible = (el) => {
    if (!el || !(el instanceof HTMLElement)) return false;
    const rect = el.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  };
  const picker =
    document.querySelector('button[aria-label="Open mode picker"]') ||
    Array.from(document.querySelectorAll('button')).find((el) => {
      const text = textOf(el);
      return visible(el) && Boolean(el.closest('bard-mode-switcher')) && /flash|pro|3\./i.test(text);
    });
  if (!picker) {
    return JSON.stringify({ selected: false, error: 'mode_picker_button_not_found' });
  }

  const before = textOf(picker);
  if (/3\.6\s*thinking/i.test(before)) {
    return JSON.stringify({ selected: true, current: before });
  }

  picker.click();
  await sleep(700);

  const candidates = Array.from(document.querySelectorAll('gem-menu-item, [role="menuitem"]'))
    .filter(visible);
  const available = candidates
    .map(textOf)
    .filter(Boolean)
    .slice(0, 20);
  const proItem = candidates.find((el) => /3\.6\s*thinking/i.test(textOf(el)));
  if (!proItem) {
    return JSON.stringify({
      selected: false,
      current: before,
      error: 'gemini_3_6_thinking_option_not_found',
      available,
    });
  }

  proItem.click();
  await sleep(1000);

  const afterPicker =
    document.querySelector('button[aria-label="Open mode picker"]') ||
    picker;
  const after = textOf(afterPicker);
  return JSON.stringify({
    selected: /3\.6\s*thinking/i.test(after),
    current: after,
    available,
    error: /3\.6\s*thinking/i.test(after) ? undefined : 'model_picker_did_not_show_3_6_thinking_after_selection',
  });
})()
`;

const SELECT_VIDEO_TOOL_JS = String.raw`
(async () => {
  const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
  const textOf = (el) => (el?.innerText || el?.textContent || '').trim().replace(/\s+/g, ' ');
  const labelOf = (el) => ((el?.getAttribute?.('aria-label') || '') + ' ' + textOf(el)).replace(/\s+/g, ' ').trim();
  const visible = (el) => {
    if (!el || !(el instanceof HTMLElement)) return false;
    const rect = el.getBoundingClientRect();
    const style = window.getComputedStyle(el);
    return rect.width > 0 && rect.height > 0 &&
      style.visibility !== 'hidden' && style.display !== 'none' &&
      Number(style.opacity || '1') > 0.05;
  };
  const selectedRe = /deselect\s+(videos?|create video)/i;
  const videoRe = /\b(create\s+video|videos?)\b/i;

  if (Array.from(document.querySelectorAll('button')).some((el) =>
    visible(el) && selectedRe.test(labelOf(el))
  )) {
    return JSON.stringify({ selected: true });
  }

  const upload = Array.from(document.querySelectorAll('button, [role="button"]')).find((el) =>
    visible(el) && /upload\s*&\s*tools/i.test((el.getAttribute('aria-label') || '') + ' ' + textOf(el))
  );
  if (!upload) {
    return JSON.stringify({ selected: false, error: 'upload_tools_button_not_found' });
  }

  upload.click();
  await sleep(700);

  const overlayItems = Array.from(document.querySelectorAll('.cdk-overlay-pane button, .cdk-overlay-pane [role="menuitem"], .cdk-overlay-pane [role="menuitemcheckbox"], .cdk-overlay-pane a, .cdk-overlay-pane gem-menu-item, toolbox-drawer-item'))
    .filter(visible);
  const available = overlayItems.map(textOf).filter(Boolean).slice(0, 30);
  const videoItem = overlayItems.find((el) => {
    const label = labelOf(el);
    return videoRe.test(label);
  });
  if (!videoItem) {
    return JSON.stringify({ selected: false, error: 'create_video_tool_option_not_found', available });
  }

  videoItem.click();
  await sleep(1200);

  const dialog = Array.from(document.querySelectorAll('[role="dialog"], mat-dialog-container, .cdk-overlay-pane'))
    .find((el) => visible(el) && /start a new chat/i.test(textOf(el)));
  if (dialog) {
    const newChat = Array.from(dialog.querySelectorAll('button, [role="button"]'))
      .find((el) => visible(el) && /^new chat$/i.test(textOf(el)));
    if (!newChat) {
      return JSON.stringify({ selected: false, error: 'start_new_chat_dialog_without_new_chat_button', available });
    }
    newChat.click();
    await sleep(1600);
  }

  const selected = Array.from(document.querySelectorAll('button')).some((el) =>
    visible(el) && selectedRe.test(labelOf(el))
  );
  return JSON.stringify({
    selected,
    available,
    error: selected ? undefined : 'create_video_tool_did_not_show_selected',
  });
})()
`;

const CLEAR_VIDEO_TOOL_JS = String.raw`
(async () => {
  const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
  const textOf = (el) => (el?.innerText || el?.textContent || '').trim().replace(/\s+/g, ' ');
  const labelOf = (el) => ((el?.getAttribute?.('aria-label') || '') + ' ' + textOf(el)).replace(/\s+/g, ' ').trim();
  const visible = (el) => {
    if (!el || !(el instanceof HTMLElement)) return false;
    const rect = el.getBoundingClientRect();
    const style = window.getComputedStyle(el);
    return rect.width > 0 && rect.height > 0 &&
      style.visibility !== 'hidden' && style.display !== 'none' &&
      Number(style.opacity || '1') > 0.05;
  };
  const selected = Array.from(document.querySelectorAll('button')).find((el) =>
    visible(el) && /deselect\s+(videos?|create video)/i.test(labelOf(el))
  );
  if (selected) {
    selected.click();
    await sleep(600);
  }
  return true;
})()
`;

const RESPONSE_COUNT_JS = String.raw`
(function(){
  return document.querySelectorAll('model-response').length;
})()
`;

const VIDEO_STATE_JS = String.raw`
(() => {
  const responses = Array.from(document.querySelectorAll('model-response'));
  const lastResponse = responses[responses.length - 1];
  const root = lastResponse || document;
  const video = root.querySelector('video') || document.querySelector('model-response video');
  const text = (lastResponse?.innerText || lastResponse?.textContent || '').trim().replace(/\s+/g, ' ').slice(0, 1000);
  const rootHasVideo = Boolean(root.querySelector('video'));
  const downloadable = Array.from(root.querySelectorAll('button, [role="button"], a')).some((el) => {
    const label = ((el.getAttribute('aria-label') || '') + ' ' + (el.innerText || el.textContent || '')).toLowerCase();
    const rect = el.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0 && label.includes('download') && (rootHasVideo || label.includes('video'));
  });
  return JSON.stringify({
    hasVideo: Boolean(video),
    duration: Number.isFinite(video?.duration) ? video.duration : undefined,
    currentTime: Number.isFinite(video?.currentTime) ? video.currentTime : undefined,
    source: video?.currentSrc || video?.src || undefined,
    downloadable,
    text,
  });
})()
`;

const DOWNLOAD_VIDEO_COORDS_JS = String.raw`
(() => {
  function visible(el) {
    const rect = el.getBoundingClientRect();
    const style = window.getComputedStyle(el);
    if (rect.width <= 2 || rect.height <= 2) return null;
    if (style.visibility === 'hidden' || style.display === 'none' || Number(style.opacity || '1') <= 0.05) return null;
    return rect;
  }
  const responses = Array.from(document.querySelectorAll('model-response'));
  const roots = responses.length > 0 ? [responses[responses.length - 1], document] : [document];
  for (const root of roots) {
    const rootHasVideo = Boolean(root.querySelector('video'));
    for (const el of root.querySelectorAll('button, [role="button"], a')) {
      const label = ((el.getAttribute('aria-label') || '') + ' ' + (el.innerText || el.textContent || '')).toLowerCase();
      if (!label.includes('download') || (!rootHasVideo && !label.includes('video'))) continue;
      const rect = visible(el);
      if (!rect) continue;
      return JSON.stringify({
        found: true,
        x: Math.round(rect.left + rect.width / 2),
        y: Math.round(rect.top + rect.height / 2),
        label,
      });
    }
  }
  return JSON.stringify({ found: false });
})()
`;

const SEND_COORDS_JS = String.raw`
(function(){
  function visible(el) {
    const rect = el.getBoundingClientRect();
    const style = window.getComputedStyle(el);
    if (rect.width <= 2 || rect.height <= 2) return null;
    if (style.visibility === 'hidden' || style.display === 'none' || Number(style.opacity || '1') <= 0.05) return null;
    return rect;
  }
  const candidates = [
    'button[aria-label*="Send" i]',
    'button[aria-label*="Submit" i]',
    'button[type="submit"]',
    '[role="button"][aria-label*="Send" i]'
  ];
  for (const selector of candidates) {
    for (const el of document.querySelectorAll(selector)) {
      const rect = visible(el);
      if (!rect) continue;
      if (el.disabled || el.getAttribute('aria-disabled') === 'true') continue;
      return JSON.stringify({
        found: true,
        x: Math.round(rect.left + rect.width / 2),
        y: Math.round(rect.top + rect.height / 2),
        label: el.getAttribute('aria-label') || el.innerText || selector
      });
    }
  }
  return JSON.stringify({ found: false });
})()
`;

const RESPONSE_STATE_JS = String.raw`
(function(needle, baselineCount, maxChars){
  function clean(text) {
    return (text || '')
      .replace(/\r/g, '')
      .replace(/\n{3,}/g, '\n\n')
      .replace(/^Gemini said\s*/i, '')
      .replace(/^\s*Show thinking\s*/i, '')
      .trim();
  }
  function visible(el) {
    const rect = el.getBoundingClientRect();
    const style = window.getComputedStyle(el);
    return rect.width > 2 && rect.height > 2 &&
      style.visibility !== 'hidden' && style.display !== 'none' &&
      Number(style.opacity || '1') > 0.05;
  }
  const bodyText = document.body.innerText || '';
  const normalizedBody = bodyText.replace(/\s+/g, ' ').trim();
  const promptFound = needle.length === 0 || normalizedBody.includes(needle);
  const responses = Array.from(document.querySelectorAll('model-response'));
  const responseCount = responses.length;
  const lastResponse = responses[responses.length - 1];
  let text = lastResponse ? clean(lastResponse.innerText || lastResponse.textContent || '') : '';
  const hasNewResponse = responseCount > baselineCount;

  if (!text && promptFound) {
    const idx = normalizedBody.lastIndexOf(needle);
    if (idx >= 0) {
      text = normalizedBody.slice(idx + needle.length).trim();
    }
  }

  let active = false;
  for (const el of document.querySelectorAll('button, [role="button"]')) {
    if (!visible(el)) continue;
    const label = ((el.innerText || el.textContent || '') + ' ' +
      (el.getAttribute('aria-label') || '') + ' ' +
      (el.getAttribute('title') || '')).toLowerCase();
    if (label.includes('stop response') || label.includes('stop generating') ||
        label.includes('cancel response') || label.includes('generating')) {
      active = true;
      break;
    }
  }

  return JSON.stringify({
    active,
    promptFound,
    responseCount,
    hasNewResponse,
    text: text.slice(0, maxChars)
  });
})
`;

function getWorkspaceConfig(): vscode.WorkspaceConfiguration {
    return vscode.workspace.getConfiguration('screenmemory');
}

function getConfigNumber(key: string, fallback: number): number {
    const value = getWorkspaceConfig().get<number>(key, fallback);
    return Number.isFinite(value) ? value : fallback;
}

function getConfigBoolean(key: string, fallback: boolean): boolean {
    return getWorkspaceConfig().get<boolean>(key, fallback);
}

function getConfigString(key: string, fallback: string): string {
    const value = getWorkspaceConfig().get<string>(key, fallback);
    return typeof value === 'string' ? value : fallback;
}

function delay(ms: number, signal?: AbortSignal): Promise<void> {
    if (signal?.aborted) {
        return Promise.resolve();
    }
    return new Promise(resolve => {
        const timer = setTimeout(() => {
            signal?.removeEventListener('abort', onAbort);
            resolve();
        }, ms);
        const onAbort = () => {
            clearTimeout(timer);
            resolve();
        };
        signal?.addEventListener('abort', onAbort, { once: true });
    });
}

function normalizeNeedle(text: string): string {
    return text.replace(/\s+/g, ' ').trim().slice(0, 140);
}

function makeToolCallId(): string {
    return `cdp_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

function normalizeTargetMode(value: string): GeminiCdpTargetMode {
    if (value === 'reuse-existing' || value === 'new-tab' || value === 'background') {
        return value;
    }
    // Backward compatibility: the retired `hidden` setting now means a real
    // background tab. Never create Target.createTarget(hidden=true).
    if (value === 'hidden') {
        return 'background';
    }
    return 'reuse-existing';
}

function isVideoRequest(request: CompletionRequest): boolean {
    const model = request.model.toLowerCase();
    return model.includes('video') || model.includes('veo');
}

function defaultVideoDownloadDir(): string {
    const workspace = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    return path.join(workspace ?? process.cwd(), 'data', 'gemini-cdp-downloads');
}

function parseJsonObject(value: string): unknown {
    try {
        return JSON.parse(value);
    } catch {
        return undefined;
    }
}

function coerceToolCalls(value: unknown): ToolCall[] {
    let rawCalls: unknown = value;

    if (value && typeof value === 'object' && !Array.isArray(value)) {
        const obj = value as Record<string, unknown>;
        rawCalls = obj.skynet_tool_calls ?? obj.tool_calls ?? obj.toolCalls ?? (
            typeof obj.name === 'string' ? [obj] : undefined
        );
    }

    if (!Array.isArray(rawCalls)) {
        return [];
    }

    const calls: ToolCall[] = [];
    for (const item of rawCalls) {
        if (!item || typeof item !== 'object') {
            continue;
        }
        const obj = item as Record<string, unknown>;
        const name = typeof obj.name === 'string' ? obj.name.trim() : '';
        if (!name) {
            continue;
        }
        const args = obj.arguments ?? obj.args ?? {};
        calls.push({
            id: typeof obj.id === 'string' ? obj.id : makeToolCallId(),
            name,
            arguments: args && typeof args === 'object' && !Array.isArray(args)
                ? args as Record<string, unknown>
                : {},
        });
    }
    return calls;
}

function findJsonPayload(text: string): { json: string; full: string } | undefined {
    const start = text.search(/[\[{]/);
    if (start < 0) {
        return undefined;
    }

    const opener = text[start];
    const closer = opener === '{' ? '}' : ']';
    let depth = 0;
    let inString = false;
    let escaped = false;

    for (let i = start; i < text.length; i++) {
        const ch = text[i];
        if (escaped) {
            escaped = false;
            continue;
        }
        if (ch === '\\') {
            escaped = true;
            continue;
        }
        if (ch === '"') {
            inString = !inString;
            continue;
        }
        if (inString) {
            continue;
        }
        if (ch === opener) {
            depth++;
        } else if (ch === closer) {
            depth--;
            if (depth === 0) {
                return {
                    json: text.slice(start, i + 1),
                    full: text.slice(0, i + 1),
                };
            }
        }
    }

    return undefined;
}

function parseToolProtocol(text: string): ParsedProviderResponse {
    const blocks: Array<{ full: string; body: string }> = [];
    const fence = /```(?:json|tool|skynet_tool_calls)?\s*([\s\S]*?)```/gi;
    let match: RegExpExecArray | null;
    while ((match = fence.exec(text)) !== null) {
        blocks.push({ full: match[0], body: match[1].trim() });
    }

    for (const block of blocks) {
        const parsed = parseJsonObject(block.body);
        const toolCalls = coerceToolCalls(parsed);
        if (toolCalls.length > 0) {
            return {
                content: text.replace(block.full, '').trim(),
                toolCalls,
            };
        }
    }

    const rawParsed = parseJsonObject(text.trim());
    const rawCalls = coerceToolCalls(rawParsed);
    if (rawCalls.length > 0) {
        return { content: '', toolCalls: rawCalls };
    }

    const labelStripped = text.trim().replace(/^(?:json|tool|skynet_tool_calls)\s*/i, '').trim();
    if (labelStripped !== text.trim()) {
        const parsed = parseJsonObject(labelStripped);
        const toolCalls = coerceToolCalls(parsed);
        if (toolCalls.length > 0) {
            return { content: '', toolCalls };
        }
    }

    const payload = findJsonPayload(text);
    if (payload) {
        const parsed = parseJsonObject(payload.json);
        const toolCalls = coerceToolCalls(parsed);
        if (toolCalls.length > 0) {
            return {
                content: text.replace(payload.full, '').trim(),
                toolCalls,
            };
        }
    }

    return { content: text, toolCalls: [] };
}

function buildToolProtocol(tools: ToolDefinition[] | undefined): string {
    if (!tools || tools.length === 0) {
        return '';
    }

    const compactTools = tools.map(tool => ({
        name: tool.name,
        description: tool.description,
        inputSchema: tool.inputSchema,
    }));

    return [
        'SKYNET TOOL BRIDGE:',
        'You have access to local Skynet tools through a CDP bridge. Tool calls are executed by Skynet, not by Gemini.',
        'Never invent tool results. If you need workspace data, edits, shell output, web fetches, or browser research, call a tool and wait for the result.',
        'When calling tools, respond with only one fenced JSON block in this exact shape:',
        '```json',
        '{"skynet_tool_calls":[{"name":"read_file","arguments":{"filePath":"D:/path/file.ts"}}]}',
        '```',
        'After Skynet provides tool results, continue normally or call another tool.',
        '',
        'Available tools:',
        JSON.stringify(compactTools, null, 2),
    ].join('\n');
}

function formatMessage(msg: ChatMessage): string {
    const prefix = msg.role.toUpperCase();
    const parts: string[] = [];

    if (msg.content) {
        parts.push(`${prefix}: ${msg.content}`);
    }

    if (msg.attachments && msg.attachments.length > 0) {
        parts.push(`${prefix} ATTACHMENTS:\n${msg.attachments.map(a =>
            `[${a.type}] ${a.name}\n${a.content}`,
        ).join('\n\n')}`);
    }

    if (msg.toolCalls && msg.toolCalls.length > 0) {
        parts.push(`ASSISTANT TOOL CALLS:\n${JSON.stringify(msg.toolCalls, null, 2)}`);
    }

    if (msg.toolResults && msg.toolResults.length > 0) {
        parts.push(`SKYNET TOOL RESULTS:\n${JSON.stringify(msg.toolResults, null, 2)}`);
    }

    return parts.join('\n\n');
}

function buildGeminiPrompt(request: CompletionRequest): string {
    const parts: string[] = [];

    parts.push('You are connected to Skynet through a Chrome DevTools Protocol bridge.');
    parts.push(`Requested model/lane: ${request.model}.`);
    parts.push('Treat the transcript below as the full conversation state for this stateless browser turn.');

    if (request.systemPrompt) {
        parts.push('', 'SYSTEM INSTRUCTIONS:', request.systemPrompt);
    }

    const toolProtocol = buildToolProtocol(request.tools);
    if (toolProtocol) {
        parts.push('', toolProtocol);
    }

    if (request.maxTokens) {
        parts.push('', `Requested max output tokens: ${request.maxTokens}.`);
    }

    parts.push('', 'TRANSCRIPT:');
    for (const msg of request.messages) {
        if (msg.role === 'system') {
            continue;
        }
        parts.push(formatMessage(msg));
    }

    parts.push('', 'Now respond to the latest user turn. Use the Skynet tool bridge if tools are needed.');
    return parts.join('\n');
}

class CdpConnection {
    private nextId = 0;
    private pending = new Map<number, {
        resolve: (value: unknown) => void;
        reject: (reason?: unknown) => void;
        timer?: ReturnType<typeof setTimeout>;
    }>();

    private constructor(private readonly ws: WebSocket) {
        this.ws.addEventListener('message', event => this.handleMessage(event));
        this.ws.addEventListener('error', () => this.rejectAll(new Error('CDP websocket error')));
        this.ws.addEventListener('close', () => this.rejectAll(new Error('CDP websocket closed')));
    }

    static connect(url: string, timeoutMs = CDP_CALL_TIMEOUT_MS): Promise<CdpConnection> {
        return new Promise((resolve, reject) => {
            const ws = new WebSocket(url);
            const timer = setTimeout(() => {
                try { ws.close(); } catch { /* best effort */ }
                reject(new Error(`CDP websocket open timed out after ${timeoutMs}ms`));
            }, timeoutMs);

            ws.addEventListener('open', () => {
                clearTimeout(timer);
                resolve(new CdpConnection(ws));
            }, { once: true });

            ws.addEventListener('error', () => {
                clearTimeout(timer);
                reject(new Error('CDP websocket open failed'));
            }, { once: true });
        });
    }

    call<T = unknown>(method: string, params: Record<string, unknown> = {}, timeoutMs = CDP_CALL_TIMEOUT_MS): Promise<T> {
        const id = ++this.nextId;
        const payload = JSON.stringify({ id, method, params });

        return new Promise<T>((resolve, reject) => {
            const pending = {
                resolve: (value: unknown) => resolve(value as T),
                reject,
                timer: undefined as ReturnType<typeof setTimeout> | undefined,
            };
            if (timeoutMs > 0) {
                pending.timer = setTimeout(() => {
                    this.pending.delete(id);
                    reject(new Error(`${method} timed out after ${timeoutMs}ms`));
                }, timeoutMs);
            }
            this.pending.set(id, pending);
            this.ws.send(payload);
        });
    }

    close(): void {
        try { this.ws.close(); } catch { /* best effort */ }
    }

    private handleMessage(event: MessageEvent): void {
        if (typeof event.data !== 'string') {
            return;
        }

        let msg: CdpResponse;
        try {
            msg = JSON.parse(event.data) as CdpResponse;
        } catch {
            return;
        }

        if (typeof msg.id !== 'number') {
            return;
        }

        const pending = this.pending.get(msg.id);
        if (!pending) {
            return;
        }
        this.pending.delete(msg.id);
        if (pending.timer) {
            clearTimeout(pending.timer);
        }
        if (msg.error) {
            pending.reject(new Error(`CDP error ${msg.error.code}: ${msg.error.message}`));
            return;
        }
        pending.resolve(msg.result);
    }

    private rejectAll(error: Error): void {
        for (const [id, pending] of this.pending) {
            if (pending.timer) {
                clearTimeout(pending.timer);
            }
            pending.reject(error);
            this.pending.delete(id);
        }
    }
}

export class GeminiCdpProvider extends AIProviderBase {
    readonly providerId = 'gemini-cdp';
    readonly displayName = 'Gemini 3.6 Thinking (CDP)';

    private readonly port: number;
    private readonly appUrl: string;
    private readonly responseTimeoutMs: number;
    private readonly closeTabAfterRequest: boolean;
    private readonly stableMs: number;
    private readonly targetMode: GeminiCdpTargetMode;
    private readonly autoDownloadVideos: boolean;
    private readonly mediaOptIn: boolean;
    private readonly videoDownloadDir: string;
    private _disposed = false;

    constructor(options: GeminiCdpOptions = {}) {
        super();
        this.port = options.port ?? getConfigNumber('geminiCdp.port', DEFAULT_CDP_PORT);
        this.appUrl = options.appUrl ?? getConfigString('geminiCdp.appUrl', DEFAULT_GEMINI_URL);
        this.responseTimeoutMs = options.responseTimeoutMs ?? getConfigNumber('geminiCdp.responseTimeoutMs', 0);
        this.closeTabAfterRequest = options.closeTabAfterRequest ?? getConfigBoolean('geminiCdp.closeTabAfterRequest', true);
        this.stableMs = options.stableMs ?? getConfigNumber('geminiCdp.stableMs', DEFAULT_STABLE_MS);
        this.targetMode = options.targetMode ?? normalizeTargetMode(getConfigString('geminiCdp.targetMode', 'reuse-existing'));
        this.autoDownloadVideos = options.autoDownloadVideos ?? getConfigBoolean('geminiCdp.autoDownloadVideos', true);
        this.mediaOptIn = options.mediaOptIn ?? getConfigBoolean('geminiCdp.mediaOptIn', false);
        this.videoDownloadDir = (options.videoDownloadDir ?? getConfigString('geminiCdp.videoDownloadDir', '')) || defaultVideoDownloadDir();
    }

    async listModels(): Promise<ModelInfo[]> {
        await this.assertCdpReachable();
        return this.mediaOptIn
            ? GEMINI_CDP_MODELS
            : GEMINI_CDP_MODELS.filter((model) => model.id === GEMINI_CDP_MODEL_ID);
    }

    async complete(request: CompletionRequest): Promise<CompletionResponse> {
        const raw = await this.runBrowserTurn(request);
        const parsed = parseToolProtocol(raw);
        return {
            content: parsed.content,
            toolCalls: parsed.toolCalls.length > 0 ? parsed.toolCalls : undefined,
            usage: {
                promptTokens: Math.ceil(buildGeminiPrompt(request).length / 4),
                completionTokens: Math.ceil(raw.length / 4),
            },
            model: request.model,
            finishReason: parsed.toolCalls.length > 0 ? 'tool_calls' : 'stop',
        };
    }

    streamComplete(request: CompletionRequest) {
        const controller = new AbortController();
        const self = this;

        async function* generate(): AsyncGenerator<StreamingChunk> {
            try {
                const raw = await self.runBrowserTurn(request, controller.signal);
                if (controller.signal.aborted) {
                    return;
                }

                const parsed = parseToolProtocol(raw);
                if (parsed.content) {
                    yield { type: 'text', content: parsed.content };
                }
                for (const toolCall of parsed.toolCalls) {
                    yield { type: 'tool_call', toolCall };
                }
                yield { type: 'done' };
            } catch (err: unknown) {
                if (controller.signal.aborted) {
                    return;
                }
                yield { type: 'error', error: err instanceof Error ? err.message : String(err) };
            }
        }

        return createStreamingResponse(generate(), controller);
    }

    async validateApiKey(_apiKey: string): Promise<boolean> {
        try {
            await this.assertCdpReachable();
            return true;
        } catch {
            return false;
        }
    }

    dispose(): void {
        this._disposed = true;
    }

    private async assertCdpReachable(): Promise<void> {
        const response = await fetch(`http://127.0.0.1:${this.port}/json/version`);
        if (!response.ok) {
            throw new Error(`Gemini CDP endpoint is not reachable on port ${this.port}`);
        }
    }

    private async runBrowserTurn(request: CompletionRequest, signal?: AbortSignal): Promise<string> {
        if (this._disposed) {
            throw new Error('Gemini CDP provider has been disposed');
        }
        if (typeof WebSocket !== 'function') {
            throw new Error('Global WebSocket is unavailable in this VS Code runtime; Gemini CDP provider requires WebSocket support.');
        }

        const prompt = buildGeminiPrompt(request);
        const promptNeedle = normalizeNeedle([...request.messages].reverse().find(m => m.role === 'user')?.content ?? prompt);
        const videoMode = isVideoRequest(request);
        if (videoMode && !this.mediaOptIn) {
            throw new Error('BLOCKED_BY_POLICY: Gemini CDP media generation requires screenmemory.geminiCdp.mediaOptIn=true');
        }
        let target: CdpTarget | undefined;
        let cdp: CdpConnection | undefined;

        try {
            target = await this.createTarget();
            if (!target.webSocketDebuggerUrl) {
                throw new Error('CDP target did not expose a websocket URL');
            }

            cdp = await CdpConnection.connect(target.webSocketDebuggerUrl);
            await cdp.call('Page.enable');
            await cdp.call('Runtime.enable');
                // Prove this is a normal-sized renderer BEFORE contacting Gemini.
            // Chrome's Target.createTarget(hidden=true) measured as visible+0x0 on
            // 2026-08-27 and triggered Google's unusual-traffic path.
            await this.assertHumanSizedTarget(cdp);
            // Reused /u/N/app tabs are already authenticated. Never collapse a proven
            // account route back to generic /app. Provider-owned targets still navigate.
            if (target.owned !== false) {
                await cdp.call('Page.navigate', { url: this.appUrl });
            }
            await delay(target.owned === false ? 800 : 3500, signal);
            this.throwIfAborted(signal);

            await this.evaluate(cdp, NEW_CHAT_CLICK_JS);
            await delay(1200, signal);
            this.throwIfAborted(signal);

            await this.ensureProModel(cdp);
            await delay(400, signal);
            this.throwIfAborted(signal);

            if (videoMode) {
                await this.ensureVideoTool(cdp);
                await delay(400, signal);
            } else {
                await this.clearVideoTool(cdp);
            }
            this.throwIfAborted(signal);

            const baselineCount = await this.evaluate<number>(cdp, RESPONSE_COUNT_JS);
            const composer = await this.focusComposer(cdp);
            if (!composer.found) {
                throw new Error(`Gemini composer not found via CDP (${composer.error ?? 'unknown'}). The browser may be signed out or blocked by a modal.`);
            }

            await cdp.call('Input.insertText', { text: prompt }, 120_000);
            await delay(400, signal);
            await this.submitPrompt(cdp);

            const text = await this.waitForResponse(cdp, promptNeedle, baselineCount, signal);
            if (!text.trim()) {
                throw new Error('Gemini CDP returned an empty response');
            }

            if (!videoMode) {
                return text;
            }

            const videoState = await this.waitForVideoState(cdp, this.autoDownloadVideos, signal);
            let downloadedPath: string | undefined;
            if (this.autoDownloadVideos && videoState.downloadable) {
                downloadedPath = await this.downloadVideo(cdp, signal).catch((err: unknown) => {
                    const message = err instanceof Error ? err.message : String(err);
                    return `DOWNLOAD_FAILED: ${message}`;
                });
            }

            return [
                text,
                '',
                'SKYNET_GEMINI_VIDEO_STATE:',
                JSON.stringify({
                    ...videoState,
                    downloadedPath,
                    targetMode: this.targetMode,
                }, null, 2),
            ].join('\n');
        } finally {
            cdp?.close();
            if (target && target.owned !== false && this.closeTabAfterRequest) {
                await this.closeTarget(target).catch(() => {});
            }
        }
    }

    private async createTarget(): Promise<CdpTarget> {
        if (this.targetMode === 'reuse-existing') {
            const existing = await this.findExistingGeminiTarget();
            if (existing) {
                return { ...existing, owned: false };
            }
            throw new Error('Gemini CDP targetMode is reuse-existing, but no existing Gemini tab is available. Open/login Gemini once or set screenmemory.geminiCdp.targetMode to new-tab.');
        }
        if (this.targetMode === 'new-tab') {
            return this.createVisibleTab();
        }
        return this.createBackgroundTarget();
    }

    private async createVisibleTab(): Promise<CdpTarget> {
        const encoded = encodeURIComponent(this.appUrl);
        const path = `/json/new?${encoded}`;
        try {
            const target = await this.cdpHttpJson<CdpTarget>(path, { method: 'PUT' });
            return { ...target, owned: true };
        } catch {
            const target = await this.cdpHttpJson<CdpTarget>(path, { method: 'GET' });
            return { ...target, owned: true };
        }
    }

    private async createBackgroundTarget(): Promise<CdpTarget> {
        const version = await this.cdpHttpJson<{ webSocketDebuggerUrl?: string }>('/json/version');
        if (!version.webSocketDebuggerUrl) {
            throw new Error('CDP browser target did not expose a websocket URL for background target creation');
        }
        const browser = await CdpConnection.connect(version.webSocketDebuggerUrl);
        try {
            const created = await browser.call<{ targetId: string }>('Target.createTarget', {
                url: 'about:blank',
                background: true,
            });
            const target = await this.waitForTarget(created.targetId);
            return { ...target, id: created.targetId, owned: true, hidden: false, ownerConnection: browser };
        } catch (err) {
            browser.close();
            throw err;
        }
    }

    private async findExistingGeminiTarget(): Promise<CdpTarget | undefined> {
        const targets = await this.cdpHttpJson<CdpTarget[]>('/json');
        const candidates = targets.filter(target =>
            target.webSocketDebuggerUrl &&
            Boolean(target.url && (
                target.url.startsWith(this.appUrl) ||
                /^https:\/\/gemini\.google\.com\/u\/\d+\/app(?:\/|$)/.test(target.url)
            )),
        );
        return candidates.find(target =>
            /^https:\/\/gemini\.google\.com\/u\/\d+\/app(?:\/|$)/.test(target.url ?? '')
        ) ?? candidates[0];
    }

    private async waitForTarget(id: string): Promise<CdpTarget> {
        for (let attempt = 0; attempt < 30; attempt++) {
            const targets = await this.cdpHttpJson<CdpTarget[]>('/json');
            const target = targets.find(item => item.id === id);
            if (target?.webSocketDebuggerUrl) {
                return target;
            }
            await delay(200);
        }
        throw new Error(`Background CDP target ${id} did not expose a websocket URL`);
    }

    private async closeTarget(target: CdpTarget): Promise<void> {
        try {
            if (target.ownerConnection) {
                await target.ownerConnection.call('Target.closeTarget', { targetId: target.id }).catch(() => {});
                return;
            }
            await fetch(`http://127.0.0.1:${this.port}/json/close/${encodeURIComponent(target.id)}`);
        } finally {
            target.ownerConnection?.close();
        }
    }

    private async cdpHttpJson<T>(path: string, init?: RequestInit): Promise<T> {
        const response = await fetch(`http://127.0.0.1:${this.port}${path}`, init);
        if (!response.ok) {
            const text = await response.text().catch(() => '');
            throw new Error(`CDP HTTP ${path} failed (${response.status}): ${text}`);
        }
        return response.json() as Promise<T>;
    }

    private async evaluate<T = unknown>(cdp: CdpConnection, expression: string, args: unknown[] = []): Promise<T> {
        let finalExpression = expression;
        if (args.length > 0) {
            finalExpression = `${expression}(${args.map(arg => JSON.stringify(arg)).join(',')})`;
        }
        const result = await cdp.call<RuntimeEvaluateResult>('Runtime.evaluate', {
            expression: finalExpression,
            returnByValue: true,
            awaitPromise: true,
        });
        if (result.exceptionDetails) {
            throw new Error(`Runtime.evaluate exception: ${JSON.stringify(result.exceptionDetails).slice(0, 1000)}`);
        }
        return result.result?.value as T;
    }

    private async assertHumanSizedTarget(cdp: CdpConnection): Promise<void> {
        const raw = await this.evaluate<string>(cdp, String.raw`
(() => JSON.stringify({
  width: window.innerWidth,
  height: window.innerHeight,
  visibility: document.visibilityState,
  webdriver: navigator.webdriver === true
}))()
`);
        let proof: { width?: number; height?: number; visibility?: string; webdriver?: boolean };
        try {
            proof = JSON.parse(raw) as typeof proof;
        } catch {
            throw new Error('Gemini CDP background-target viewport proof was not parseable');
        }
        if ((proof.width ?? 0) < 800 || (proof.height ?? 0) < 600) {
            throw new Error(`Gemini CDP refused non-human viewport ${proof.width ?? 0}x${proof.height ?? 0}`);
        }
        if (proof.webdriver) {
            throw new Error('Gemini CDP refused a navigator.webdriver=true target');
        }
    }

    private async focusComposer(cdp: CdpConnection): Promise<ComposerInfo> {
        const raw = await this.evaluate<string>(cdp, COMPOSER_FOCUS_JS);
        try {
            return JSON.parse(raw) as ComposerInfo;
        } catch {
            return { found: false, error: 'composer_result_parse_failed' };
        }
    }

    private async ensureProModel(cdp: CdpConnection): Promise<void> {
        const raw = await this.evaluate<string>(cdp, SELECT_PRO_MODEL_JS);
        let info: ModelSelectionInfo;
        try {
            info = JSON.parse(raw) as ModelSelectionInfo;
        } catch {
            throw new Error('Gemini CDP model-selection result was not parseable');
        }
        if (!info.selected) {
            const available = info.available?.length ? ` Available: ${info.available.join(' | ')}` : '';
            throw new Error(`Gemini CDP could not select Gemini 3.6 Thinking (${info.error ?? 'unknown'}). Current: ${info.current ?? 'unknown'}.${available}`);
        }
    }

    private async ensureVideoTool(cdp: CdpConnection): Promise<void> {
        const raw = await this.evaluate<string>(cdp, SELECT_VIDEO_TOOL_JS);
        let info: VideoAppSelectionInfo;
        try {
            info = JSON.parse(raw) as VideoAppSelectionInfo;
        } catch {
            throw new Error('Gemini CDP video-tool selection result was not parseable');
        }
        if (!info.selected) {
            const available = info.available?.length ? ` Available: ${info.available.join(' | ')}` : '';
            throw new Error(`Gemini CDP could not select the Videos app (${info.error ?? 'unknown'}).${available}`);
        }
    }

    private async clearVideoTool(cdp: CdpConnection): Promise<void> {
        await this.evaluate(cdp, CLEAR_VIDEO_TOOL_JS);
    }

    private async getVideoState(cdp: CdpConnection): Promise<VideoState> {
        const raw = await this.evaluate<string>(cdp, VIDEO_STATE_JS);
        try {
            return JSON.parse(raw) as VideoState;
        } catch {
            return { hasVideo: false, downloadable: false, text: raw };
        }
    }

    private async waitForVideoState(cdp: CdpConnection, requireDownload: boolean, signal?: AbortSignal): Promise<VideoState> {
        let lastState: VideoState | undefined;
        while (!signal?.aborted) {
            const state = await this.getVideoState(cdp);
            lastState = state;
            const stateText = state.text?.toLowerCase() ?? '';
            if (
                !state.hasVideo &&
                /\b(couldn't|could not|failed|error|unable to generate|try again|policy)\b/i.test(stateText)
            ) {
                throw new Error(`Gemini video generation failed: ${state.text?.slice(0, 500) ?? 'unknown error'}`);
            }
            if (requireDownload ? state.downloadable : state.hasVideo) {
                return state;
            }
            await delay(5000, signal);
        }
        this.throwIfAborted(signal);
        return lastState ?? { hasVideo: false, downloadable: false };
    }

    private async downloadVideo(cdp: CdpConnection, signal?: AbortSignal): Promise<string> {
        await fs.promises.mkdir(this.videoDownloadDir, { recursive: true });
        const downloadBehavior = {
            behavior: 'allow',
            downloadPath: this.videoDownloadDir,
        };
        await cdp.call('Browser.setDownloadBehavior', downloadBehavior)
            .catch(() => cdp.call('Page.setDownloadBehavior', downloadBehavior));

        const start = Date.now();
        const raw = await this.evaluate<string>(cdp, DOWNLOAD_VIDEO_COORDS_JS);
        let coords: { found?: boolean; x?: number; y?: number };
        try {
            coords = JSON.parse(raw) as { found?: boolean; x?: number; y?: number };
        } catch {
            coords = {};
        }
        if (!coords.found || typeof coords.x !== 'number' || typeof coords.y !== 'number') {
            throw new Error('Gemini video download button was not found');
        }

        await this.click(cdp, coords.x, coords.y);
        return this.waitForDownloadedVideo(start, signal);
    }

    private async waitForDownloadedVideo(startTimeMs: number, signal?: AbortSignal): Promise<string> {
        let candidate: { file: string; size: number } | undefined;
        while (!signal?.aborted) {
            const entries = await fs.promises.readdir(this.videoDownloadDir, { withFileTypes: true }).catch(() => []);
            const files = await Promise.all(entries
                .filter(entry => entry.isFile())
                .map(async entry => {
                    const file = path.join(this.videoDownloadDir, entry.name);
                    const stat = await fs.promises.stat(file).catch(() => undefined);
                    return stat ? { file, stat } : undefined;
                }));
            const newest = files
                .filter((item): item is { file: string; stat: fs.Stats } => Boolean(item))
                .filter(item => item.stat.mtimeMs >= startTimeMs - 1000)
                .filter(item => !item.file.toLowerCase().endsWith('.crdownload'))
                .filter(item => VIDEO_EXTENSIONS.has(path.extname(item.file).toLowerCase()))
                .sort((a, b) => b.stat.mtimeMs - a.stat.mtimeMs)[0];

            if (newest) {
                if (candidate?.file === newest.file && candidate.size === newest.stat.size) {
                    return newest.file;
                }
                candidate = { file: newest.file, size: newest.stat.size };
            }
            await delay(1000, signal);
        }
        this.throwIfAborted(signal);
        throw new Error(`Gemini video download was aborted before a stable file appeared in ${this.videoDownloadDir}`);
    }

    private async submitPrompt(cdp: CdpConnection): Promise<void> {
        const raw = await this.evaluate<string>(cdp, SEND_COORDS_JS);
        let coords: { found?: boolean; x?: number; y?: number };
        try {
            coords = JSON.parse(raw) as { found?: boolean; x?: number; y?: number };
        } catch {
            coords = {};
        }

        if (coords.found && typeof coords.x === 'number' && typeof coords.y === 'number') {
            await this.click(cdp, coords.x, coords.y);
            return;
        }

        await cdp.call('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Enter', code: 'Enter' });
        await cdp.call('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter' });
    }

    private async click(cdp: CdpConnection, x: number, y: number): Promise<void> {
        await cdp.call('Input.dispatchMouseEvent', {
            type: 'mousePressed',
            x,
            y,
            button: 'left',
            clickCount: 1,
        });
        await cdp.call('Input.dispatchMouseEvent', {
            type: 'mouseReleased',
            x,
            y,
            button: 'left',
            clickCount: 1,
        });
    }

    private async waitForResponse(
        cdp: CdpConnection,
        promptNeedle: string,
        baselineCount: number,
        signal?: AbortSignal,
    ): Promise<string> {
        const start = Date.now();
        let lastText = '';
        let stableSince = 0;
        let bestText = '';

        while (!signal?.aborted) {
            if (this.responseTimeoutMs > 0 && Date.now() - start > this.responseTimeoutMs) {
                throw new Error(`Gemini CDP response timed out after ${Math.round(this.responseTimeoutMs / 1000)}s`);
            }

            const raw = await this.evaluate<string>(
                cdp,
                RESPONSE_STATE_JS,
                [promptNeedle, baselineCount, MAX_RESPONSE_CHARS],
            );
            let state: ResponseState | undefined;
            try {
                state = JSON.parse(raw) as ResponseState;
            } catch {
                state = undefined;
            }

            const text = state?.text?.trim() ?? '';
            if (text.length > bestText.length) {
                bestText = text;
            }

            if (text && text === lastText) {
                stableSince = stableSince || Date.now();
            } else {
                stableSince = 0;
                lastText = text;
            }

            const stableFor = stableSince ? Date.now() - stableSince : 0;
            if (
                text &&
                (state?.hasNewResponse || (state?.responseCount ?? 0) > baselineCount) &&
                !state?.active &&
                stableFor >= this.stableMs
            ) {
                return text;
            }

            await delay(POLL_MS, signal);
        }

        this.throwIfAborted(signal);
        return bestText;
    }

    private throwIfAborted(signal?: AbortSignal): void {
        if (signal?.aborted) {
            throw new Error('Gemini CDP request aborted');
        }
    }
}
