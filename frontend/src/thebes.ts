// thebes.ts — minimal browser client for a Thebes backend canister.
//
// Talks the node HTTP surface the way the substrate's own dapps do
// (sample-dapp / memphis-client pattern):
//
//   query:  POST /api/query    { canister_id, method, arg, sender }
//   update: GET  /api/next_nonce?sender=…
//           POST /api/call     { canister_id, method, arg, sender, nonce }
//           GET  /api/receipt?hash=…   (poll until the chain finalizes)
//
// `arg` and `reply` are hex-encoded Candid bytes. This file hand-rolls
// exactly the Candid subset the starter backend uses — text, nat,
// nat64 — so the template has zero runtime dependencies. Grow it as
// your interface grows, or swap in a full Candid library later.

export const BACKEND_CANISTER_ID = 176438213872974;

// Same-origin when served from the chain via the boundary
// (/_/raw/<cid>/…). The Vite dev server proxies /api there too, so
// `npm run dev` works against the live network out of the box.
const BASE = "";

// ─── hex ─────────────────────────────────────────────────────────────

function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.length % 2 ? "0" + hex : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

// ─── LEB128 (unsigned + signed) ──────────────────────────────────────

function uleb(n: bigint): number[] {
  const out: number[] = [];
  for (;;) {
    const byte = Number(n & 0x7fn);
    n >>= 7n;
    if (n === 0n) {
      out.push(byte);
      return out;
    }
    out.push(byte | 0x80);
  }
}

function ulebDecode(buf: Uint8Array, off: number): [bigint, number] {
  let result = 0n;
  let shift = 0n;
  for (;;) {
    const byte = buf[off++];
    if (byte === undefined) throw new Error("candid: truncated uleb128");
    result |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) return [result, off];
    shift += 7n;
  }
}

function slebDecode(buf: Uint8Array, off: number): [bigint, number] {
  let result = 0n;
  let shift = 0n;
  for (;;) {
    const byte = buf[off++];
    if (byte === undefined) throw new Error("candid: truncated sleb128");
    result |= BigInt(byte & 0x7f) << shift;
    shift += 7n;
    if ((byte & 0x80) === 0) {
      if (byte & 0x40) result -= 1n << shift; // sign-extend
      return [result, off];
    }
  }
}

// ─── Candid encode (the subset the starter needs) ────────────────────

const MAGIC = [0x44, 0x49, 0x44, 0x4c]; // "DIDL"
const TYPE_TEXT_SLEB = 0x71; // sleb128(-15), the `text` type code

/// Encode zero arguments: `()`.
export function encodeEmpty(): string {
  return bytesToHex(new Uint8Array([...MAGIC, 0, 0]));
}

/// Encode a single `(text)` argument.
export function encodeText(s: string): string {
  const utf8 = new TextEncoder().encode(s);
  return bytesToHex(
    new Uint8Array([
      ...MAGIC,
      0, // empty type table (primitives don't need entries)
      1, // one argument
      TYPE_TEXT_SLEB,
      ...uleb(BigInt(utf8.length)),
      ...utf8,
    ])
  );
}

// ─── Candid decode (text | nat | nat64) ──────────────────────────────

/// Decode a single-value Candid reply. Supports the primitive returns
/// the starter backend produces: text (0x71), nat (0x7d), nat64 (0x78).
export function decodeReply(hex: string): string | bigint {
  const buf = hexToBytes(hex);
  if (buf.length < 6 || buf[0] !== 0x44 || buf[1] !== 0x49 || buf[2] !== 0x44 || buf[3] !== 0x4c) {
    throw new Error("candid: bad magic in reply");
  }
  let off = 4;
  let tableCount: bigint;
  [tableCount, off] = ulebDecode(buf, off);
  if (tableCount !== 0n) {
    throw new Error(
      "candid: reply uses compound types; this starter client decodes primitives only — extend thebes.ts"
    );
  }
  let argCount: bigint;
  [argCount, off] = ulebDecode(buf, off);
  if (argCount === 0n) return "";
  let ty: bigint;
  [ty, off] = slebDecode(buf, off);
  switch (ty) {
    case -15n: {
      // text
      let len: bigint;
      [len, off] = ulebDecode(buf, off);
      return new TextDecoder().decode(buf.slice(off, off + Number(len)));
    }
    case -3n: {
      // nat
      const [v] = ulebDecode(buf, off);
      return v;
    }
    case -8n: {
      // nat64, 8 bytes little-endian
      let v = 0n;
      for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(buf[off + i]);
      return v;
    }
    default:
      throw new Error(`candid: unsupported reply type ${ty}; extend thebes.ts`);
  }
}

// ─── sender identity (demo-grade) ────────────────────────────────────
//
// Updates need a sender + nonce. This starter uses a random per-browser
// sender kept in localStorage — enough for the demo counter. For real
// user identity, integrate Memphis (the substrate's identity layer).

function demoSender(): string {
  // Scoped per backend cid. localStorage is per-ORIGIN, and every app on
  // the gateway shares one origin, so an unscoped key hands the SAME
  // sender to every project — their nonce sequences then interleave and
  // one app's submit gets rejected as a replay of another's.
  const KEY = `thebes-demo-sender:${BACKEND_CANISTER_ID}`;
  let s = localStorage.getItem(KEY);
  if (!s) {
    const b = new Uint8Array(8);
    crypto.getRandomValues(b);
    s = bytesToHex(b);
    localStorage.setItem(KEY, s);
  }
  return s;
}

// ─── transient-tolerant fetch ─────────────────────────────────────────
//
// The boundary fans out to a validator set; when one validator is
// briefly unreachable the gateway answers 502 with
// "validator unreachable". That is transient — the next attempt routes
// elsewhere. Retry a few times with backoff so a healthy cluster never
// surfaces a scary error to the user. Only idempotent reads and the
// pre-submit steps use this; the submitted update itself is never
// retried (that could double-execute), its receipt is polled instead.

const RETRIES = 3;

function isTransient(status: number, body: string): boolean {
  return (
    status === 502 ||
    status === 503 ||
    status === 504 ||
    /validator unreachable|no healthy validator|unhealthy/i.test(body)
  );
}

async function fetchWithRetry(url: string, init?: RequestInit): Promise<any> {
  let lastErr = "";
  for (let attempt = 0; attempt <= RETRIES; attempt++) {
    if (attempt > 0) {
      await new Promise((r) => setTimeout(r, 400 * attempt));
    }
    try {
      const r = await fetch(url, init);
      const text = await r.text();
      if (!r.ok && isTransient(r.status, text)) {
        lastErr = `HTTP ${r.status}: ${text.slice(0, 200)}`;
        continue;
      }
      try {
        return JSON.parse(text);
      } catch {
        throw new Error(`malformed reply: ${text.slice(0, 200)}`);
      }
    } catch (e) {
      // Network-level failure (DNS, connection reset) — also transient.
      lastErr = String(e);
    }
  }
  throw new Error(`the network is briefly unreachable — please try again (${lastErr})`);
}

// ─── the three motions ───────────────────────────────────────────────

export async function query(method: string, argHex: string): Promise<string | bigint> {
  const j = await fetchWithRetry(`${BASE}/api/query`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      canister_id: BACKEND_CANISTER_ID,
      method,
      arg: argHex,
      sender: demoSender(),
    }),
  });
  if (j.status !== "success") throw new Error(j.error || "query failed");
  return decodeReply(j.reply || "");
}

async function submitCall(
  method: string,
  argHex: string,
  sender: string,
  nonce: number
): Promise<any> {
  // The submit itself is deliberately NOT retried on a transient: a retry
  // after a submit that actually landed would execute the update twice.
  const r = await fetch(`${BASE}/api/call`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      canister_id: BACKEND_CANISTER_ID,
      method,
      arg: argHex,
      sender,
      nonce,
    }),
  });
  const text = await r.text();
  if (!r.ok && isTransient(r.status, text)) {
    throw new Error("the network is briefly unreachable — please try again");
  }
  return JSON.parse(text);
}

export async function call(method: string, argHex: string): Promise<string | bigint> {
  const sender = demoSender();
  const nj = await fetchWithRetry(`${BASE}/api/next_nonce?sender=${sender}`, {
    cache: "no-store",
  });
  if (typeof nj.next_nonce !== "number") throw new Error("malformed next_nonce reply");

  let j = await submitCall(method, argHex, sender, nj.next_nonce);

  // Nonce recovery. A replay rejection means the nonce we were given was
  // behind the substrate's replay set — the call did NOT execute, so
  // re-submitting is safe. The rejection helpfully names the real
  // high-water mark ("nonce 0 already used (last seen: 8)"), so resubmit
  // at last_seen + 1 rather than guessing.
  if (!j.queued && typeof j.error === "string" && /nonce .* already used/i.test(j.error)) {
    const m = j.error.match(/last seen:\s*(\d+)/i);
    const recovered = m ? Number(m[1]) + 1 : nj.next_nonce + 1;
    j = await submitCall(method, argHex, sender, recovered);
  }

  if (!j.queued || !j.message_hash) throw new Error(j.error || "call rejected");
  return pollReceipt(j.message_hash);
}

async function pollReceipt(hashHex: string): Promise<string | bigint> {
  const deadline = Date.now() + 30_000;
  let transientPolls = 0;
  while (Date.now() < deadline) {
    try {
      const j = await fetchWithRetry(`${BASE}/api/receipt?hash=${hashHex}`);
      if (j.found) {
        if (j.status === "success") return decodeReply(j.reply || "");
        throw new Error(j.error || "call failed on chain");
      }
    } catch (e) {
      // A transient during polling is not a failed call — the update may
      // still be in flight. Keep polling until the deadline.
      if (++transientPolls > 10) throw e;
    }
    await new Promise((res) => setTimeout(res, 500));
  }
  throw new Error("timed out waiting for the chain's receipt");
}
