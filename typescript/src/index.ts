import { createHmac, timingSafeEqual } from "node:crypto";

const origin = "https://verify.blocksign.io";

export interface MeetingBinding {
  channel: string;
  meetingId: string | null;
}

export interface DeviceReports {
  isHuman?: boolean | null;
  livenessScore?: number | null;
  faceMatch?: { outcome: string; score?: number | null } | null;
  "18years"?: boolean | null;
}

export interface Verdict {
  reported?: DeviceReports & { source: string };
  server?: {
    source: string;
    corroborated: boolean;
    livenessScore?: number | null;
    floor?: number | null;
    floorMeans?: string;
  };
}

interface VerificationData extends DeviceReports {
  sessionId: number;
  status?: string;
  schemaVersion?: number;
  verdict?: Verdict | null;
  answers?: unknown;
  idDocumentData?: unknown;
  livenessChecks?: unknown;
  meeting?: MeetingBinding | null;
  completedAt?: string | null;
}

export interface VerificationResult extends VerificationData {
  uid: string;
  status: string;
  createdAt?: string;
}

export interface WebhookEvent extends VerificationData {
  event: "verification.completed";
  token: string;
  uid: string | null;
  proof?: string | null;
}

export type MeetingProofResult =
  | { valid: false; reason: string }
  | {
      valid: true;
      sessionId: number;
      orgId?: number;
      human: boolean;
      meeting: MeetingBinding;
      expiresAt: string;
    };

export class VerifyApiError extends Error {
  readonly retryable: boolean;

  constructor(
    public readonly kind: "transport" | "http" | "response",
    public readonly status: number | null,
  ) {
    super(kind === "http" ? `BlockSign Verify returned HTTP ${status}.` :
      kind === "transport" ? "BlockSign Verify request failed." :
        "BlockSign Verify returned an unexpected response.");
    this.name = "VerifyApiError";
    this.retryable = kind === "transport" || (kind === "http" &&
      status !== null && (status === 408 || status === 429 || status >= 500));
  }
}

export class VerifyWebhookError extends Error {
  constructor(public readonly kind: "signature" | "payload") {
    super(kind === "signature" ? "Invalid BlockSign Verify webhook signature." :
      "Invalid BlockSign Verify webhook payload.");
    this.name = "VerifyWebhookError";
  }
}

export interface VerifyClientOptions {
  apiKey?: string;
  timeoutMs?: number;
  fetch?: typeof globalThis.fetch;
}

export class VerifyClient {
  readonly #apiKey?: string;
  readonly #timeoutMs: number;
  readonly #fetch: typeof globalThis.fetch;

  constructor(options: VerifyClientOptions = {}) {
    this.#apiKey = options.apiKey;
    this.#timeoutMs = options.timeoutMs ?? 10_000;
    if (!Number.isInteger(this.#timeoutMs) || this.#timeoutMs < 1 || this.#timeoutMs > 2_147_483_647) {
      throw new RangeError("timeoutMs must be a positive number of milliseconds within the Node.js timer range.");
    }
    this.#fetch = options.fetch ?? globalThis.fetch;
  }

  async checkVerification(uid: string): Promise<VerificationResult> {
    requireUid(uid);
    if (!this.#apiKey?.trim() || /[\r\n\0]/.test(this.#apiKey)) {
      throw new TypeError("A valid API key is required to check a verification.");
    }
    const { body, status } = await this.#get("/api/check", { uid }, this.#apiKey);
    if (body.uid !== uid || !sessionId(body.sessionId) || typeof body.status !== "string") {
      throw new VerifyApiError("response", status);
    }
    return body as unknown as VerificationResult;
  }

  async verifyMeetingProof(proof?: string | null): Promise<MeetingProofResult> {
    const { body, status } = await this.#get("/api/proof/verify", proof ? { proof } : {}, undefined, !proof);
    if (body.valid === false && typeof body.reason === "string" && body.reason.length > 0) {
      return body as MeetingProofResult;
    }
    const meeting = record(body.meeting);
    if (body.valid === true && sessionId(body.sessionId) && typeof body.human === "boolean" &&
        (body.orgId === undefined || sessionId(body.orgId)) &&
        typeof meeting?.channel === "string" && (meeting.meetingId === null || typeof meeting.meetingId === "string") &&
        typeof body.expiresAt === "string" && Number.isFinite(Date.parse(body.expiresAt))) {
      return body as unknown as MeetingProofResult;
    }
    throw new VerifyApiError("response", status);
  }

  async #get(path: string, query: Record<string, string>, apiKey?: string, missingProof = false) {
    const url = new URL(path, origin);
    url.search = new URLSearchParams(query).toString();
    const headers: Record<string, string> = { Accept: "application/json", "Cache-Control": "no-store" };
    if (apiKey !== undefined) headers["X-API-Key"] = apiKey;
    let response: Response;
    const signal = AbortSignal.timeout(this.#timeoutMs);
    try {
      response = await this.#fetch(url, { method: "GET", headers, redirect: "manual", signal });
    } catch {
      throw new VerifyApiError("transport", null);
    }
    const legacyMissing = missingProof && response.status === 400;
    if (!response.ok && !legacyMissing) throw new VerifyApiError("http", response.status);

    let data: string;
    try {
      data = await response.text();
    } catch {
      throw new VerifyApiError("transport", null);
    }
    const body = parseObject(data);
    if (legacyMissing) {
      if (body?.valid === false &&
          (body.reason === "missing" || body.error === "Missing proof query parameter")) {
        return { body: { valid: false, reason: "missing" }, status: response.status };
      }
      throw new VerifyApiError("http", response.status);
    }
    if (!body) throw new VerifyApiError("response", response.status);
    return { body, status: response.status };
  }
}

/** Use the current static link from the Verify dashboard. */
export function buildVerificationUrl(verificationLink: string, uid: string): string {
  requireUid(uid);
  const url = new URL(verificationLink);
  if (url.origin !== origin || url.username || url.password || !/^\/v\/[^/]+\/?$/.test(url.pathname)) {
    throw new TypeError("Expected a static https://verify.blocksign.io/v/ verification link.");
  }
  url.searchParams.set("uid", uid);
  return url.toString();
}

/** Call on a successful Check response or an authenticated webhook. */
export function isCorroborated(result: Pick<VerificationData, "schemaVersion" | "status" | "verdict">): boolean {
  return result.schemaVersion === 2 && result.status === "completed" &&
    result.verdict?.server?.corroborated === true;
}

/** Supply the untouched request body and the X-BlockSign-Signature header. */
export function verifyWebhookSignature(
  rawBody: Uint8Array | string,
  signature: string | null | undefined,
  secret: string,
): boolean {
  if (!secret || typeof signature !== "string" || signature.length !== 64 || !/^[a-f0-9]{64}$/i.test(signature)) {
    return false;
  }
  const expected = createHmac("sha256", secret).update(rawBody).digest();
  return timingSafeEqual(expected, Buffer.from(signature, "hex"));
}

export function parseWebhook(
  rawBody: Uint8Array | string,
  signature: string | null | undefined,
  secret: string,
): WebhookEvent {
  if (!verifyWebhookSignature(rawBody, signature, secret)) throw new VerifyWebhookError("signature");
  const body = parseObject(typeof rawBody === "string" ? rawBody : Buffer.from(rawBody).toString("utf8"));
  if (!body || body.event !== "verification.completed" || !sessionId(body.sessionId) ||
      typeof body.token !== "string" || (body.uid !== null && typeof body.uid !== "string")) {
    throw new VerifyWebhookError("payload");
  }
  return body as unknown as WebhookEvent;
}

function requireUid(uid: string): void {
  if (!uid.trim() || !uid.isWellFormed()) throw new TypeError("uid must be a non-empty Unicode string.");
}

function sessionId(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function record(value: unknown): Record<string, unknown> | undefined {
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
}

function parseObject(json: string): Record<string, unknown> | undefined {
  try {
    return record(JSON.parse(json));
  } catch {
    return undefined;
  }
}
