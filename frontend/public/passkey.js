/*
 * Memphis passkey sign-in client (browser, no framework).
 *
 * Talks to:
 *   POST /api/call                    (boundary passthrough → validator /api/call)
 *   GET  /api/receipt?hash=<hex>      (boundary passthrough → validator /api/receipt)
 *   POST /api/v1/canister/921/query   (boundary query passthrough)
 *
 * Surface exposed at window.MemphisPasskey:
 *   register(name)               -> { name, anchor_id_hex, session_token_hex, expires_at_ns, display_tag }
 *   signIn(name)                 -> { name, anchor_id_hex, session_token_hex, expires_at_ns, display_tag }
 *   signInOrRegister(name)       -> auto-decide via anchor_for_name lookup
 *   whoami(session_token_hex)    -> { anchor_id_hex, expires_at_ns, display_tag }
 *   lookupName(name)             -> principal hex or null
 *   loadSession()                -> { name, anchor_id_hex, session_token_hex, expires_at_ns, display_tag } | null
 *   saveSession(session)
 *   clearSession()               -> localStorage-only (legacy; does not revoke server-side)
 *   signOut()                    -> async; calls end_session on canister, then clearSession()
 *
 * The Memphis canister is at cid 921; RP_ID matches the page's origin
 * (memphis.mercaturaforum.com). Showcase build of the canister accepts a
 * single passkey factor at registration (MIN_FACTORS_AT_SIGNUP=1).
 */
(function (global) {
    "use strict";

    const MEMPHIS_CID = 921;
    const BOUNDARY = location.origin.includes("memphis.mercaturaforum.com")
        ? ""
        : "https://memphis.mercaturaforum.com";
    const RP_ID = "memphis.mercaturaforum.com";

    // ─── tiny utilities ────────────────────────────────────────────────────
    function bytesToHex(u8) {
        let s = "";
        for (let i = 0; i < u8.length; i++) s += u8[i].toString(16).padStart(2, "0");
        return s;
    }
    function hexToBytes(hex) {
        if (hex.length & 1) throw new Error("odd-length hex");
        const out = new Uint8Array(hex.length / 2);
        for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
        return out;
    }
    function concat(...arrs) {
        let total = 0;
        for (const a of arrs) total += a.length;
        const out = new Uint8Array(total);
        let off = 0;
        for (const a of arrs) { out.set(a, off); off += a.length; }
        return out;
    }
    function randomBytes(n) {
        const u = new Uint8Array(n);
        crypto.getRandomValues(u);
        return u;
    }
    const utf8 = new TextEncoder();
    const utf8d = new TextDecoder();

    // ─── LEB128 ────────────────────────────────────────────────────────────
    function uleb(n) {
        if (typeof n === "number") n = BigInt(n);
        const out = [];
        while (true) {
            let b = Number(n & 0x7fn);
            n >>= 7n;
            if (n === 0n) { out.push(b); return out; }
            out.push(b | 0x80);
        }
    }
    function sleb(n) {
        if (typeof n === "number") n = BigInt(n);
        const out = [];
        while (true) {
            let b = Number(n & 0x7fn);
            const sign = (b & 0x40) !== 0;
            n >>= 7n;
            if ((n === 0n && !sign) || (n === -1n && sign)) { out.push(b); return out; }
            out.push(b | 0x80);
        }
    }
    function readUleb(u8, off) {
        let r = 0n, shift = 0n, b;
        do {
            b = u8[off++];
            r |= BigInt(b & 0x7f) << shift;
            shift += 7n;
        } while (b & 0x80);
        return [r, off];
    }
    function readSleb(u8, off) {
        let r = 0n, shift = 0n, b;
        while (true) {
            b = u8[off++];
            r |= BigInt(b & 0x7f) << shift;
            shift += 7n;
            if ((b & 0x80) === 0) {
                if (shift < 64n && (b & 0x40)) r |= -(1n << shift);
                return [r, off];
            }
        }
    }

    // ─── Candid: a hand-written builder targeting only the shapes we need ──
    //
    // We emit a self-contained type table per call. For multi-arg methods we
    // build several arg type entries. This is the Candid 0.x wire format.
    //
    //   T_text       = sleb(-15)
    //   T_blob       = sleb(-19) sleb(-5)         ; vec nat8
    //   T_nat64      = sleb(-8)
    //   T_record(fs) = sleb(-20) uleb(count) (uleb(hash) sleb(type)){count}
    //   T_vec(t)     = sleb(-19) sleb(t)
    //
    // For arg encoding:
    //   text   : uleb(len) bytes
    //   blob   : uleb(len) bytes
    //   nat64  : 8 little-endian bytes
    //   record : each field in hash-sorted order
    //   vec    : uleb(len) then each element
    function candidFieldHash(name) {
        let h = 0n;
        for (const c of utf8.encode(name)) h = (h * 223n + BigInt(c)) & 0xffffffffn;
        return Number(h);
    }
    const TY = { TEXT: -15, BLOB_BYTES: -5, OPT: -18, VEC: -19, RECORD: -20, NAT64: -8 };

    // A FactorRegistration / FactorAssertion record shares the same field set
    // (with one extra field on registration).
    const FACTOR_REG_FIELDS = [
        // name -> primitive type code for the field's value
        ["credential_id", "blob"],
        ["cose_pub_key_bytes", "blob"],
        ["authenticator_data", "blob"],
        ["client_data_json", "blob"],
        ["signature", "blob"],
    ];
    const FACTOR_ASSERT_FIELDS = [
        ["credential_id", "blob"],
        ["authenticator_data", "blob"],
        ["client_data_json", "blob"],
        ["signature", "blob"],
    ];

    // Encode `(vec FactorRegistration)`. Three type-table entries: T0 is
    // `vec nat8` (blob), T1 is the record whose fields ALL reference T0,
    // T2 is `vec T1`. Field type-refs in T1 are POSITIVE-SLEB type-table
    // indices, not inline `vec nat8` opcodes — Candid forbids compound
    // types (vec, opt, record, variant) appearing inline at a field's
    // type-ref position; they MUST appear in the type table and the
    // field references the index.
    function encVecFactorRegistration(factors) {
        const sorted = FACTOR_REG_FIELDS
            .map(([n, t]) => ({ name: n, hash: candidFieldHash(n), t }))
            .sort((a, b) => a.hash - b.hash);
        const out = [];
        out.push(0x44, 0x49, 0x44, 0x4c);
        out.push(...uleb(3));
        // T0 = vec nat8 (blob)
        out.push(...sleb(TY.VEC));
        out.push(...sleb(TY.BLOB_BYTES));
        // T1 = record { fields → T0 }
        out.push(...sleb(TY.RECORD));
        out.push(...uleb(sorted.length));
        for (const f of sorted) {
            out.push(...uleb(f.hash));
            out.push(...sleb(0)); // type ref → T0
        }
        // T2 = vec T1
        out.push(...sleb(TY.VEC));
        out.push(...sleb(1)); // type ref → T1
        // 1 arg of type T2
        out.push(...uleb(1));
        out.push(...sleb(2));
        // value
        out.push(...uleb(factors.length));
        for (const f of factors) {
            for (const fd of sorted) {
                const v = f[fd.name];
                if (!(v instanceof Uint8Array)) throw new Error("factor field " + fd.name + " must be Uint8Array");
                out.push(...uleb(v.length));
                for (const b of v) out.push(b);
            }
        }
        return new Uint8Array(out);
    }

    // Encode `(FactorAssertion)`. Two type-table entries: T0 is
    // `vec nat8` (blob), T1 is the record whose fields ALL reference T0.
    // Same rule as encVecFactorRegistration: compound types live in the
    // type table; field type-refs are positive-sleb indices.
    function encFactorAssertion(assertion) {
        const sorted = FACTOR_ASSERT_FIELDS
            .map(([n, t]) => ({ name: n, hash: candidFieldHash(n), t }))
            .sort((a, b) => a.hash - b.hash);
        const out = [];
        out.push(0x44, 0x49, 0x44, 0x4c);
        out.push(...uleb(2));
        // T0 = vec nat8 (blob)
        out.push(...sleb(TY.VEC));
        out.push(...sleb(TY.BLOB_BYTES));
        // T1 = record { fields → T0 }
        out.push(...sleb(TY.RECORD));
        out.push(...uleb(sorted.length));
        for (const f of sorted) {
            out.push(...uleb(f.hash));
            out.push(...sleb(0)); // type ref → T0
        }
        // 1 arg of type T1
        out.push(...uleb(1));
        out.push(...sleb(1));
        for (const fd of sorted) {
            const v = assertion[fd.name];
            if (!(v instanceof Uint8Array)) throw new Error("assertion field " + fd.name + " must be Uint8Array");
            out.push(...uleb(v.length));
            for (const b of v) out.push(b);
        }
        return new Uint8Array(out);
    }

    // Encode `(blob)` single arg.
    function encBlob(bytes) {
        const out = [];
        out.push(0x44, 0x49, 0x44, 0x4c);
        out.push(...uleb(1));
        out.push(...sleb(TY.VEC));
        out.push(...sleb(TY.BLOB_BYTES));
        out.push(...uleb(1));
        out.push(...sleb(0));
        out.push(...uleb(bytes.length));
        for (const b of bytes) out.push(b);
        return new Uint8Array(out);
    }

    // Encode `(text)` single arg.
    function encText(s) {
        const bytes = utf8.encode(s);
        const out = [];
        out.push(0x44, 0x49, 0x44, 0x4c);
        out.push(...uleb(0));
        out.push(...uleb(1));
        out.push(...sleb(TY.TEXT));
        out.push(...uleb(bytes.length));
        for (const b of bytes) out.push(b);
        return new Uint8Array(out);
    }

    // Encode `(blob, text, text, nat64)` for claim_name.
    function encClaimNameArgs(token, name, origin, version) {
        const tokenBytes = token instanceof Uint8Array ? token : hexToBytes(token);
        const nameBytes = utf8.encode(name);
        const originBytes = utf8.encode(origin);
        const out = [];
        out.push(0x44, 0x49, 0x44, 0x4c);
        // T0 = blob (vec nat8)
        out.push(...uleb(1));
        out.push(...sleb(TY.VEC));
        out.push(...sleb(TY.BLOB_BYTES));
        // 4 args: T0, text, text, nat64
        out.push(...uleb(4));
        out.push(...sleb(0));
        out.push(...sleb(TY.TEXT));
        out.push(...sleb(TY.TEXT));
        out.push(...sleb(TY.NAT64));
        // value: blob
        out.push(...uleb(tokenBytes.length));
        for (const b of tokenBytes) out.push(b);
        // value: text name
        out.push(...uleb(nameBytes.length));
        for (const b of nameBytes) out.push(b);
        // value: text origin
        out.push(...uleb(originBytes.length));
        for (const b of originBytes) out.push(b);
        // value: nat64 (LE)
        const v = BigInt(version);
        for (let i = 0n; i < 8n; i++) out.push(Number((v >> (i * 8n)) & 0xffn));
        return new Uint8Array(out);
    }

    // ─── Candid: small reply decoder that walks the wire format ────────────
    //
    // We don't build a general decoder; instead, each reply shape has a
    // dedicated routine that knows what to expect. This keeps the parser
    // small and easy to audit.

    function skipTypeTable(u8, off) {
        // We don't *use* the type table for the value walker — the canister
        // emits a well-known shape per method — but we have to advance past
        // it. Each type def is a sleb followed by a variable structure.
        const [tts, a1] = readUleb(u8, off); off = a1;
        for (let i = 0n; i < tts; i++) {
            const [code, a2] = readSleb(u8, off); off = a2;
            if (code === -20n || code === -21n) {
                // record / variant: uleb count, then (hash sleb, type-ref sleb) pairs
                const [cnt, a3] = readUleb(u8, off); off = a3;
                for (let j = 0n; j < cnt; j++) {
                    const [_h, a4] = readUleb(u8, off); off = a4;
                    const [_t, a5] = readSleb(u8, off); off = a5;
                }
            } else if (code === -18n || code === -19n) {
                // opt / vec: one inner type-ref
                const [_t, a3] = readSleb(u8, off); off = a3;
            } else if (code === -22n) {
                // func: arg-vec, ret-vec, ann-vec — we don't expect these
                throw new Error("func type unexpected");
            } else if (code === -23n) {
                throw new Error("service type unexpected");
            }
            // primitive (-1..-15) and references take no further bytes
        }
        // arg count + arg type refs
        const [args, a6] = readUleb(u8, off); off = a6;
        for (let i = 0n; i < args; i++) {
            const [_t, a7] = readSleb(u8, off); off = a7;
        }
        return off;
    }

    function expectDidlMagic(u8) {
        if (u8.length < 4 || u8[0] !== 0x44 || u8[1] !== 0x49 || u8[2] !== 0x44 || u8[3] !== 0x4c) {
            throw new Error("reply missing DIDL magic");
        }
        return 4;
    }

    // Decode a `variant { Ok : blob; Err : MemphisError }` reply where Ok is blob.
    function decodeResultBlob(replyBytes) {
        let off = expectDidlMagic(replyBytes);
        off = skipTypeTable(replyBytes, off);
        const [tag, a1] = readUleb(replyBytes, off); off = a1;
        if (tag === 0n) {
            const [len, a2] = readUleb(replyBytes, off); off = a2;
            return { ok: replyBytes.slice(off, off + Number(len)) };
        }
        return { err: extractErrorTag(replyBytes, off, tag) };
    }

    // Decode a `variant { Ok; Err : MemphisError }` reply where Ok carries no
    // payload (used by end_session). Returns { ok: true } or { err: {...} }.
    function decodeResultEmpty(replyBytes) {
        let off = expectDidlMagic(replyBytes);
        off = skipTypeTable(replyBytes, off);
        const [tag, a1] = readUleb(replyBytes, off); off = a1;
        if (tag === 0n) return { ok: true };
        return { err: extractErrorTag(replyBytes, off, tag) };
    }

    // Decode a `variant { Ok : record { anchor_id : blob; session_token : blob; expires_at_ns : nat64 }; Err : MemphisError }`.
    // We rely on the canister always emitting fields in hash-sorted order
    // (Candid mandates this); the actual hashes are:
    //   anchor_id      = candidFieldHash("anchor_id")      = 0x00B2D8B8 = 11721912
    //   session_token  = candidFieldHash("session_token")  = ...
    //   expires_at_ns  = candidFieldHash("expires_at_ns")  = ...
    // We compute the three hashes, sort them, and decode in that order.
    function decodeResultRecordReg(replyBytes) {
        let off = expectDidlMagic(replyBytes);
        off = skipTypeTable(replyBytes, off);
        const [tag, a1] = readUleb(replyBytes, off); off = a1;
        if (tag === 0n) {
            const order = sortedFieldOrder([
                ["anchor_id", "blob"],
                ["session_token", "blob"],
                ["expires_at_ns", "nat64"],
                ["display_tag", "text"],
            ]);
            const rec = {};
            for (const fd of order) {
                if (fd.t === "blob") {
                    const [len, ax] = readUleb(replyBytes, off); off = ax;
                    rec[fd.name] = replyBytes.slice(off, off + Number(len));
                    off += Number(len);
                } else if (fd.t === "nat64") {
                    let v = 0n;
                    for (let i = 0n; i < 8n; i++) v |= BigInt(replyBytes[off + Number(i)]) << (i * 8n);
                    rec[fd.name] = v;
                    off += 8;
                } else if (fd.t === "text") {
                    const [len, ax] = readUleb(replyBytes, off); off = ax;
                    rec[fd.name] = utf8d.decode(replyBytes.slice(off, off + Number(len)));
                    off += Number(len);
                }
            }
            return { ok: rec };
        }
        return { err: extractErrorTag(replyBytes, off, tag) };
    }

    function decodeResultRecordAuth(replyBytes) {
        let off = expectDidlMagic(replyBytes);
        off = skipTypeTable(replyBytes, off);
        const [tag, a1] = readUleb(replyBytes, off); off = a1;
        if (tag === 0n) {
            const order = sortedFieldOrder([
                ["session_token", "blob"],
                ["expires_at_ns", "nat64"],
            ]);
            const rec = {};
            for (const fd of order) {
                if (fd.t === "blob") {
                    const [len, ax] = readUleb(replyBytes, off); off = ax;
                    rec[fd.name] = replyBytes.slice(off, off + Number(len));
                    off += Number(len);
                } else if (fd.t === "nat64") {
                    let v = 0n;
                    for (let i = 0n; i < 8n; i++) v |= BigInt(replyBytes[off + Number(i)]) << (i * 8n);
                    rec[fd.name] = v;
                    off += 8;
                }
            }
            return { ok: rec };
        }
        return { err: extractErrorTag(replyBytes, off, tag) };
    }

    // Decode `(opt blob)` reply for anchor_for_name / lookup_name.
    function decodeOptBlob(replyBytes) {
        let off = expectDidlMagic(replyBytes);
        off = skipTypeTable(replyBytes, off);
        const present = replyBytes[off++];
        if (present === 0) return null;
        const [len, a1] = readUleb(replyBytes, off); off = a1;
        return replyBytes.slice(off, off + Number(len));
    }

    // Decode `(variant { Ok : text; Err : MemphisError })` for claim_name.
    function decodeResultText(replyBytes) {
        let off = expectDidlMagic(replyBytes);
        off = skipTypeTable(replyBytes, off);
        const [tag, a1] = readUleb(replyBytes, off); off = a1;
        if (tag === 0n) {
            const [len, a2] = readUleb(replyBytes, off); off = a2;
            return { ok: utf8d.decode(replyBytes.slice(off, off + Number(len))) };
        }
        return { err: extractErrorTag(replyBytes, off, tag) };
    }

    function sortedFieldOrder(fields) {
        return fields.map(([n, t]) => ({ name: n, hash: candidFieldHash(n), t }))
                     .sort((a, b) => a.hash - b.hash);
    }

    // Inspect the variant payload after the tag — we don't decode the
    // MemphisError exhaustively, we just stringify the tag id for display.
    // VENDORED-PATCH (thebes-deploy new, 2026-07-28) — decode the REAL error.
    //
    // Upstream passed the OUTER Result tag (0=Ok, 1=Err) into a table whose
    // index 1 is "NotAuthenticated", so EVERY Memphis error was reported as
    // NotAuthenticated and the actual cause was never read. `off` already
    // points just past the outer tag, i.e. at the inner MemphisError variant
    // index, so decode that instead.
    //
    // Candid orders variant fields by field-name hash (h = h*223 + byte,
    // mod 2^32), NOT declaration order, so this table is hash-sorted:
    //   0 InvariantViolation  1 FactorNotFound   2 ChallengeExpired
    //   3 Unauthorized        4 DuplicateCredential  5 NotAuthenticated
    //   6 InvalidArgument     7 InsufficientFactors  8 SessionExpired
    //   9 AnchorNotFound
    function extractErrorTag(u8, off, tag) {
        const NAMES = [
            "InvariantViolation", "FactorNotFound", "ChallengeExpired", "Unauthorized",
            "DuplicateCredential", "NotAuthenticated", "InvalidArgument",
            "InsufficientFactors", "SessionExpired", "AnchorNotFound",
        ];
        if (Number(tag) === 0) return { tag: 0, name: "Ok" };
        let name, detail, inner;
        try {
            const [idx, a1] = readUleb(u8, off);
            inner = Number(idx);
            name = NAMES[inner] || "variant#" + inner;
            // Payload-carrying variants: surface the text, which is where the
            // canister puts the actionable reason.
            if (name === "InvalidArgument") {
                const [len, a2] = readUleb(u8, a1);
                detail = utf8d.decode(u8.slice(a2, a2 + Number(len)));
            } else if (name === "InvariantViolation") {
                const [ilen, a2] = readUleb(u8, a1);
                const id = utf8d.decode(u8.slice(a2, a2 + Number(ilen)));
                const [dlen, a3] = readUleb(u8, a2 + Number(ilen));
                const det = utf8d.decode(u8.slice(a3, a3 + Number(dlen)));
                detail = id + ": " + det;
            }
        } catch (_) {
            name = "undecodable-error";
        }
        return {
            tag: inner,
            name: detail ? name + " (" + detail + ")" : name,
        };
    }

    // ─── boundary transport ────────────────────────────────────────────────
    // VENDORED-PATCH (thebes-deploy new, 2026-07-28) — transient tolerance.
    //
    // The boundary fans out to a validator set that flaps in and out. When it
    // cannot reach the validator it picked, it answers with
    // {"status":"error","error":"validator unreachable: ..."}. Upstream threw
    // on that immediately, so a healthy chain surfaced a hard failure mid
    // sign-in / sign-out. A "could not deliver" answer is proof the envelope
    // never executed, so re-sending is safe and cannot double-apply.
    function isTransientTransportErr(text) {
        if (!text) return false;
        return /validator unreachable|no healthy validator|all validators are unhealthy|502|503|504/i
            .test(String(text));
    }

    async function postJsonWithRetry(url, payload, label, allowRetry) {
        const RETRIES = allowRetry === false ? 0 : 4;
        let last = "";
        for (let attempt = 0; attempt <= RETRIES; attempt++) {
            if (attempt > 0) await new Promise(r => setTimeout(r, 500 * attempt));
            let res;
            try {
                res = await fetch(url, {
                    method: "POST",
                    headers: { "content-type": "application/json" },
                    body: JSON.stringify(payload),
                }).then(r => r.json());
            } catch (e) {
                last = String(e);
                continue; // network-level blip; also non-delivery
            }
            if (res && res.error && isTransientTransportErr(res.error)) {
                last = res.error;
                continue;
            }
            return res;
        }
        throw new Error(
            label + ": the network is briefly unreachable — please try again (" + last + ")"
        );
    }

    // Methods that are SAFE to re-send after a proven non-delivery.
    //
    // `begin_registration` / `begin_authentication` mint a fresh challenge per
    // call, so an extra one is harmless (it just expires unused).
    // `end_session` is idempotent.
    //
    // Everything else is EXCLUDED on purpose. `register` and `authenticate`
    // CONSUME a single-use challenge: if a submission actually landed and the
    // gateway merely failed to report it, a re-send finds the challenge gone
    // and fails with `ChallengeExpired` — turning a recoverable blip into a
    // confusing dead end. `claim_name` commits state. For those, surface the
    // transport error and let the human retry the whole ceremony, which
    // re-mints a challenge.
    const RETRY_SAFE_METHODS = new Set([
        "begin_registration",
        "begin_authentication",
        "end_session",
    ]);

    async function memphisCallAwait(method, argBytes) {
        const argHex = bytesToHex(argBytes);
        // Anonymous calls need a fresh sender per submission, otherwise the
        // validator's per-(sender, nonce) replay set rejects the second call
        // from "sender=""" with "nonce 0 already used". We don't sign these
        // envelopes (the canister auths via WebAuthn factor proofs, not
        // msg_caller), so a random 32-byte sender is fine for transport.
        const sender = bytesToHex(randomBytes(32));
        const callRes = await postJsonWithRetry(
            BOUNDARY + "/api/call",
            { canister_id: MEMPHIS_CID, method, arg: argHex, sender },
            "call",
            RETRY_SAFE_METHODS.has(method)
        );
        if (callRes.error) throw new Error("call: " + callRes.error);
        if (!callRes.message_hash) throw new Error("call: missing message_hash in response");
        const hash = callRes.message_hash;
        // Poll up to ~8 s — single-canister cluster finalises in ~200 ms,
        // so this is generous but bounded.
        const deadline = Date.now() + 8000;
        let lastLifecycle = "submitted";
        // VENDORED-PATCH: back off while the gateway is refusing. At a flat
        // 150ms a flapping cluster produces ~50 console 502s per call, which
        // buries the real error. Steps 150→1200ms on consecutive transients
        // and snaps back the moment one lands.
        let pollDelayMs = 150;
        while (Date.now() < deadline) {
            await new Promise(r => setTimeout(r, pollDelayMs));
            let rec;
            try {
                const recRes = await fetch(BOUNDARY + "/api/receipt?hash=" + hash);
                rec = await recRes.json().catch(() => ({}));
            } catch (_) {
                // Network-level blip; treat exactly like a gateway transient.
                pollDelayMs = Math.min(pollDelayMs * 2, 1200);
                continue;
            }
            lastLifecycle = rec.lifecycle || lastLifecycle;
            if (rec.status === "success" && rec.reply) {
                return hexToBytes(rec.reply);
            }
            if (rec.status === "error") {
                // A gateway "validator unreachable" during polling is NOT a
                // canister rejection — the call may still be in flight. Keep
                // polling until the deadline instead of reporting a failure
                // the canister never issued.
                if (isTransientTransportErr(rec.error)) {
                    pollDelayMs = Math.min(pollDelayMs * 2, 1200);
                    continue;
                }
                throw new Error("canister error: " + (rec.error || "unknown"));
            }
            pollDelayMs = 150; // a clean answer — resume tight polling
        }
        throw new Error("receipt poll timeout (last lifecycle=" + lastLifecycle + ")");
    }

    function bytesToBase64(u8) {
        let s = "";
        for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
        return btoa(s);
    }
    function base64ToBytes(b64) {
        const bin = atob(b64);
        const u = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
        return u;
    }
    async function memphisQuery(method, argBytes) {
        const argB64 = bytesToBase64(argBytes);
        const res = await postJsonWithRetry(
            BOUNDARY + "/api/v1/canister/" + MEMPHIS_CID + "/query",
            { method, arg: argB64, sender: "" },
            "query"
        );
        if (res.status !== "success") throw new Error("query: " + (res.error || res.status));
        if (!res.reply) throw new Error("query: empty reply");
        // /api/v1/canister/{cid}/query returns reply as base64; /api/receipt
        // (used by memphisCallAwait below) returns it as hex.
        return base64ToBytes(res.reply);
    }

    // ─── CBOR (the minimum needed to extract authData) ─────────────────────
    function cborRead(buf, off) {
        const initial = buf[off++];
        const major = initial >> 5;
        const ai = initial & 0x1f;
        let val;
        if (ai < 24) val = ai;
        else if (ai === 24) { val = buf[off++]; }
        else if (ai === 25) { val = (buf[off++] << 8) | buf[off++]; }
        else if (ai === 26) {
            val = ((buf[off++] << 24) >>> 0) + (buf[off++] << 16) + (buf[off++] << 8) + buf[off++];
            val = val >>> 0;
        } else if (ai === 27) {
            // 8-byte length — rarely used at WebAuthn scale; reject for safety.
            throw new Error("CBOR 64-bit length unsupported");
        } else {
            throw new Error("CBOR indef/reserved unsupported ai=" + ai);
        }
        if (major === 0) return [val, off];
        if (major === 1) return [-1 - val, off];
        if (major === 2) return [buf.slice(off, off + val), off + val];
        if (major === 3) return [utf8d.decode(buf.slice(off, off + val)), off + val];
        if (major === 4) {
            const arr = [];
            for (let i = 0; i < val; i++) { const [v, o] = cborRead(buf, off); arr.push(v); off = o; }
            return [arr, off];
        }
        if (major === 5) {
            const map = new Map();
            for (let i = 0; i < val; i++) {
                const [k, o1] = cborRead(buf, off); off = o1;
                const [v, o2] = cborRead(buf, off); off = o2;
                map.set(typeof k === "string" ? k : k, v);
            }
            return [map, off];
        }
        if (major === 6) {
            // tagged value — read the inner item; we ignore tags.
            return cborRead(buf, off);
        }
        throw new Error("unsupported CBOR major: " + major);
    }

    // Given the raw CBOR-encoded attestation object, extract authData bytes.
    function extractAuthData(attestationObject) {
        const [obj] = cborRead(attestationObject, 0);
        if (!(obj instanceof Map)) throw new Error("attestation object is not a CBOR map");
        const authData = obj.get("authData");
        if (!(authData instanceof Uint8Array)) throw new Error("attestation missing authData bytes");
        return authData;
    }

    // Parse the authData layout and return { credentialId, credentialPublicKeyBytes }.
    // Layout:
    //   rpIdHash (32) | flags (1) | signCount (4) | aaguid (16) |
    //   credentialIdLength (2 BE) | credentialId (var) |
    //   credentialPublicKey (CBOR-encoded COSE_Key, var)
    function parseAttestedCredentialData(authData) {
        if (authData.length < 37 + 18) throw new Error("authData too short for attested credential data");
        const flags = authData[32];
        if ((flags & 0x40) === 0) throw new Error("authData flag AT (attested credential data) not set");
        let off = 37; // skip rpIdHash + flags + signCount
        off += 16;   // skip aaguid
        const credIdLen = (authData[off] << 8) | authData[off + 1];
        off += 2;
        const credentialId = authData.slice(off, off + credIdLen);
        off += credIdLen;
        // The COSE key is a single CBOR object starting at off; we need its
        // exact byte span so the canister can re-parse it.
        const start = off;
        const [_obj, end] = cborRead(authData, off);
        const credentialPublicKeyBytes = authData.slice(start, end);
        return { credentialId, credentialPublicKeyBytes };
    }

    // ─── WebAuthn ceremonies ───────────────────────────────────────────────
    //
    // Registration is a create()+get() PAIR over the same canister-issued
    // challenge, with attestation:"none":
    //   1. create() mints the credential; we extract only the COSE public key
    //      from authData (we do NOT use the attestation statement — "none"
    //      works on iOS/macOS Safari and Android, which don't emit "packed").
    //   2. get() immediately produces a real "webauthn.get" assertion over the
    //      same challenge — a standard ECDSA-P256 sig over
    //      authData ‖ SHA-256(clientDataJSON). The canister's INV-MEM-7
    //      verifier REQUIRES clientDataJSON.type == "webauthn.get" (see
    //      crates/memphis-webauthn verify_assertion), so the create-only
    //      ("webauthn.create") path is rejected.
    // Two user-presence prompts (one per ceremony); works on every device.
    async function webauthnCreate(challengeBytes, displayName) {
        // create()+get() PAIR over the same challenge. create() with
        // attestation:"none" mints the credential (we only need the COSE public
        // key from authData — no attStmt, so it works on iOS/macOS Safari and
        // Android which return "none"). An immediate get() yields a real
        // "webauthn.get" assertion, which the canister's INV-MEM-7 REQUIRES
        // (clientDataJSON.type must be "webauthn.get" — see crates/memphis-webauthn
        // verify_assertion). Two user-presence prompts; works on every device.
        const created = await navigator.credentials.create({
            publicKey: {
                challenge: challengeBytes,
                rp: { id: RP_ID, name: "Memphis" },
                user: {
                    id: randomBytes(32),
                    name: displayName,
                    displayName: displayName,
                },
                pubKeyCredParams: [{ type: "public-key", alg: -7 }],
                // residentKey "required": sign-in (passkey.js signIn) calls
                // get() with an EMPTY allowCredentials list — that flow only
                // finds DISCOVERABLE credentials. Platform passkeys are
                // always discoverable, but security keys and other
                // non-resident authenticators minted here could never sign
                // back in. requireResidentKey is the WebAuthn L1 spelling
                // for older clients.
                authenticatorSelection: {
                    residentKey: "required",
                    requireResidentKey: true,
                    userVerification: "preferred",
                },
                timeout: 60000,
                attestation: "none",
            },
        });
        if (!created) throw new Error("navigator.credentials.create returned null");
        const credentialId = new Uint8Array(created.rawId);
        const attestationObject = new Uint8Array(created.response.attestationObject);

        // Parse the CBOR attestationObject only to pull authData → COSE pubkey.
        const [obj] = cborRead(attestationObject, 0);
        if (!(obj instanceof Map)) throw new Error("attestationObject is not a CBOR map");
        const authData = obj.get("authData");
        if (!(authData instanceof Uint8Array)) {
            throw new Error("attestationObject missing authData");
        }
        const { credentialPublicKeyBytes } = parseAttestedCredentialData(authData);

        // Immediate get() over the SAME challenge → "webauthn.get" assertion.
        const assertion = await navigator.credentials.get({
            publicKey: {
                challenge: challengeBytes,
                rpId: RP_ID,
                allowCredentials: [
                    { type: "public-key", id: credentialId, transports: ["internal", "hybrid", "usb", "nfc", "ble"] },
                ],
                userVerification: "preferred",
                timeout: 60000,
            },
        });
        if (!assertion) throw new Error("navigator.credentials.get returned null (registration probe)");
        return {
            credentialId,
            cose_pub_key_bytes: credentialPublicKeyBytes,
            authenticator_data: new Uint8Array(assertion.response.authenticatorData),
            client_data_json: new Uint8Array(assertion.response.clientDataJSON),
            signature: new Uint8Array(assertion.response.signature),
        };
    }

    async function webauthnGet(challengeBytes, allowCredentialIds) {
        const cred = await navigator.credentials.get({
            publicKey: {
                challenge: challengeBytes,
                rpId: RP_ID,
                allowCredentials: (allowCredentialIds || []).map(id => ({
                    type: "public-key",
                    id,
                    transports: ["internal", "hybrid", "usb", "nfc", "ble"],
                })),
                userVerification: "preferred",
                timeout: 60000,
            },
        });
        if (!cred) throw new Error("navigator.credentials.get returned null");
        return {
            credentialId: new Uint8Array(cred.rawId),
            authenticatorData: new Uint8Array(cred.response.authenticatorData),
            clientDataJSON: new Uint8Array(cred.response.clientDataJSON),
            signature: new Uint8Array(cred.response.signature),
        };
    }

    // ─── High-level flows ──────────────────────────────────────────────────
    function validateName(name) {
        const n = name.trim().toLowerCase();
        if (!n.endsWith(".thebes")) throw new Error("name must end with .thebes");
        const stem = n.slice(0, -".thebes".length);
        if (stem.length < 3 || stem.length > 32) throw new Error("name stem must be 3-32 chars");
        if (!/^[a-z0-9-]+$/.test(stem)) throw new Error("name stem may only contain a-z 0-9 -");
        if (stem.startsWith("-") || stem.endsWith("-")) throw new Error("stem may not start/end with -");
        return n;
    }

    async function lookupAnchor(name) {
        const reply = await memphisQuery("anchor_for_name", encText(name));
        return decodeOptBlob(reply);
    }

    async function lookupNameToPrincipal(name) {
        const reply = await memphisQuery("lookup_name", encText(name));
        return decodeOptBlob(reply);
    }

    async function nameForPrincipal(principalBytes) {
        const reply = await memphisQuery("name_for", encBlob(principalBytes));
        // (opt text) reply
        let off = expectDidlMagic(reply);
        off = skipTypeTable(reply, off);
        const present = reply[off++];
        if (present === 0) return null;
        const [len, a1] = readUleb(reply, off); off = a1;
        return utf8d.decode(reply.slice(off, off + Number(len)));
    }

    async function register(name) {
        const validated = validateName(name);
        // 1. begin_registration -> 32-byte challenge
        const challengeReply = await memphisCallAwait("begin_registration", new Uint8Array([0x44, 0x49, 0x44, 0x4c, 0x00, 0x00]));
        const dec = decodeResultBlob(challengeReply);
        if (dec.err) throw new Error("begin_registration: " + dec.err.name);
        const challenge = dec.ok;
        // VENDORED-PATCH: the challenge is single-use with a 5-minute TTL, and
        // `ChallengeExpired` is returned BOTH for "timed out" and for "not
        // found" (already consumed, or lost because CHALLENGES is deliberately
        // non-persisted heap state — see canisters/memphis/src/lib.rs:1476).
        // Those are very different faults, so record the elapsed time; it is
        // the only way to tell them apart from the client.
        const challengeIssuedAt = Date.now();

        // 2. Pair of WebAuthn ceremonies (create + immediate get over same challenge)
        const factor = await webauthnCreate(challenge, validated);

        // 3. register([factor])
        const regReply = await memphisCallAwait(
            "register",
            encVecFactorRegistration([
                {
                    credential_id: factor.credentialId,
                    cose_pub_key_bytes: factor.cose_pub_key_bytes,
                    authenticator_data: factor.authenticator_data,
                    client_data_json: factor.client_data_json,
                    signature: factor.signature,
                },
            ])
        );
        const regDec = decodeResultRecordReg(regReply);
        if (regDec.err) {
            const elapsedMs = Date.now() - challengeIssuedAt;
            if (String(regDec.err.name).startsWith("ChallengeExpired")) {
                const withinTtl = elapsedMs < 5 * 60 * 1000;
                throw new Error(
                    "register: ChallengeExpired after " + Math.round(elapsedMs / 1000) + "s — " +
                    (withinTtl
                        ? "well inside the 5-minute TTL, so the challenge was consumed or " +
                          "dropped rather than timed out (the canister keeps challenges in " +
                          "non-persisted heap; an in-flight ceremony aborts if that state " +
                          "resets). Click create again — a new challenge is minted."
                        : "the 5-minute TTL genuinely elapsed. Click create again and " +
                          "approve the passkey prompt promptly.")
                );
            }
            throw new Error("register: " + regDec.err.name);
        }
        const anchorIdHex = bytesToHex(regDec.ok.anchor_id);
        const sessionTokenHex = bytesToHex(regDec.ok.session_token);

        // 4. claim_name (binds the handle to the per-app principal for THIS origin).
        const claimReply = await memphisCallAwait(
            "claim_name",
            encClaimNameArgs(regDec.ok.session_token, validated, location.origin, 0)
        );
        const claimDec = decodeResultText(claimReply);
        if (claimDec.err) throw new Error("claim_name: " + claimDec.err.name);

        const session = {
            name: validated,
            anchor_id_hex: anchorIdHex,
            session_token_hex: sessionTokenHex,
            expires_at_ns: regDec.ok.expires_at_ns.toString(),
            // Display tag = last 4 hex chars of anchor_id_hex. The canister
            // returns the canonical value in `regDec.ok.display_tag`; if that
            // field is missing (older canister), fall back to deriving it
            // client-side from anchor_id_hex (same formula, same result).
            display_tag: regDec.ok.display_tag || anchorIdHex.slice(-4),
        };
        saveSession(session);
        return session;
    }

    async function signIn(name) {
        const validated = validateName(name);
        const anchorBytes = await lookupAnchor(validated);
        if (!anchorBytes) throw new Error("no Memphis identity for " + validated + " — register first");
        // 1. begin_authentication(anchor_id)
        const challengeReply = await memphisCallAwait("begin_authentication", encBlob(anchorBytes));
        const dec = decodeResultBlob(challengeReply);
        if (dec.err) throw new Error("begin_authentication: " + dec.err.name);
        const challenge = dec.ok;
        // 2. navigator.credentials.get with allowCredentials = [] so the
        //    authenticator surfaces all stored credentials matching the rp.
        //    (We don't track credential ids client-side; the canister will
        //    refuse if the asserted credential_id isn't bound to the anchor.)
        const assertion = await webauthnGet(challenge, []);
        // 3. authenticate
        const authReply = await memphisCallAwait("authenticate", encFactorAssertion({
            credential_id: assertion.credentialId,
            authenticator_data: assertion.authenticatorData,
            client_data_json: assertion.clientDataJSON,
            signature: assertion.signature,
        }));
        const authDec = decodeResultRecordAuth(authReply);
        if (authDec.err) throw new Error("authenticate: " + authDec.err.name);
        const session = {
            name: validated,
            anchor_id_hex: bytesToHex(anchorBytes),
            session_token_hex: bytesToHex(authDec.ok.session_token),
            expires_at_ns: authDec.ok.expires_at_ns.toString(),
            // AuthResult doesn't carry display_tag (the reply is just token +
            // expiry); derive it client-side from anchor_id. The canister
            // uses the same formula in lib.rs:display_tag().
            display_tag: bytesToHex(anchorBytes).slice(-4),
        };
        saveSession(session);
        return session;
    }

    // P1.4 — never silently mint a NEW anchor under a name the user expected to
    // sign INTO. If the name resolves, sign in. If it does not, the caller must
    // explicitly opt into creation (`{ confirmCreate: true }`) after asking the
    // user; otherwise we throw a typed `NameNotRegistered` so the UI can confirm.
    // (Before this fix, a lookup miss silently re-registered — the "silent
    // re-registration" bug. P0.1 stable storage removed the main trigger, but
    // this closes the unsafe path itself.)
    async function signInOrRegister(name, opts) {
        const validated = validateName(name);
        const anchorBytes = await lookupAnchor(validated);
        if (anchorBytes) return signIn(validated);
        if (opts && opts.confirmCreate === true) return register(validated);
        const err = new Error("No Memphis identity exists for \"" + validated + "\".");
        err.code = "NameNotRegistered";
        err.nameRequested = validated;
        throw err;
    }

    // ─── session storage ───────────────────────────────────────────────────
    // VENDORED-PATCH (thebes-deploy new, 2026-07-29) — per-app session scope.
    //
    // localStorage is keyed by ORIGIN, not by path. Every app deployed to the
    // gateway is served from the SAME origin
    // (https://<gateway>/_/raw/<cid>/…), so a fixed key means a brand-new
    // project silently opens already signed in with another app's session —
    // observed live: a freshly deployed project inherited the previous
    // project's session. Apps set `window.MEMPHIS_SESSION_SCOPE` (the
    // scaffolder emits the backend cid) to get their own slot.
    //
    // NOTE what this does NOT fix: Memphis derives the per-app principal from
    // `location.origin`, so two apps on the same gateway host still resolve to
    // the SAME on-chain identity. That is a property of path-based hosting,
    // not of this key. Per-app principals require per-app origins.
    const STORAGE_KEY =
        "memphisSessionV1" +
        (typeof window !== "undefined" && window.MEMPHIS_SESSION_SCOPE
            ? ":" + window.MEMPHIS_SESSION_SCOPE
            : "");

    function loadSession() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            if (!raw) return null;
            const s = JSON.parse(raw);
            if (!s.session_token_hex || !s.anchor_id_hex || !s.name) return null;
            // Back-fill display_tag for sessions stored before P1.2 landed.
            // Same formula as canisters/memphis/src/lib.rs:display_tag().
            if (!s.display_tag) s.display_tag = s.anchor_id_hex.slice(-4);
            return s;
        } catch (_) { return null; }
    }
    function saveSession(s) {
        try { localStorage.setItem(STORAGE_KEY, JSON.stringify(s)); } catch (_) {}
    }
    function clearSession() {
        try { localStorage.removeItem(STORAGE_KEY); } catch (_) {}
    }

    // ─── P1.1.6: durable revoke-retry queue (Service Worker) ────────────────
    //
    // Shared IndexedDB contract (MUST match sw.js):
    //   db    = "memphis-revoke-db" v1
    //   store = "pending", keyPath "token_hex"
    //   rec   = { token_hex, arg_hex, queued_at_ns, expires_at_ns, attempts }
    //
    // The page writes the entry BEFORE the canister call so a page-close
    // mid-revoke doesn't lose it; the Service Worker drains it with retry.
    const REVOKE_DB = "memphis-revoke-db";
    const REVOKE_DB_VERSION = 1;
    const REVOKE_STORE = "pending";
    const REVOKE_SYNC_TAG = "memphis-revoke-retry";

    function openRevokeDb() {
        return new Promise(function (resolve, reject) {
            if (!global.indexedDB) { reject(new Error("no indexedDB")); return; }
            const req = indexedDB.open(REVOKE_DB, REVOKE_DB_VERSION);
            req.onupgradeneeded = function () {
                const db = req.result;
                if (!db.objectStoreNames.contains(REVOKE_STORE)) {
                    db.createObjectStore(REVOKE_STORE, { keyPath: "token_hex" });
                }
            };
            req.onsuccess = function () { resolve(req.result); };
            req.onerror = function () { reject(req.error); };
        });
    }

    // keyPath = token_hex → put() overwrites, so the same token never
    // double-queues (acceptance #5 dedup). Fail-soft on any IDB error.
    async function queueRevoke(tokenHex, argHex, expiresAtNs) {
        try {
            const db = await openRevokeDb();
            await new Promise(function (resolve, reject) {
                const tx = db.transaction(REVOKE_STORE, "readwrite");
                tx.objectStore(REVOKE_STORE).put({
                    token_hex: tokenHex,
                    arg_hex: argHex,
                    queued_at_ns: String(BigInt(Date.now()) * 1000000n),
                    expires_at_ns: String(expiresAtNs || "0"),
                    attempts: 0,
                });
                tx.oncomplete = resolve;
                tx.onerror = function () { reject(tx.error); };
            });
        } catch (_) { /* fail-soft: no IDB → revoke is one-shot best-effort */ }
    }

    async function dequeueRevoke(tokenHex) {
        try {
            const db = await openRevokeDb();
            await new Promise(function (resolve, reject) {
                const tx = db.transaction(REVOKE_STORE, "readwrite");
                tx.objectStore(REVOKE_STORE).delete(tokenHex);
                tx.oncomplete = resolve;
                tx.onerror = function () { reject(tx.error); };
            });
        } catch (_) { /* fail-soft */ }
    }

    // Register the Service Worker + wire the page-driven retry triggers
    // (initial drain + window 'online'). Background Sync (Chrome/Edge) handles
    // page-close durability; the message path covers Safari/Firefox while a
    // page is open. Idempotent — safe to call from every page's init.
    function registerRevokeWorker() {
        if (!("serviceWorker" in navigator)) return;
        navigator.serviceWorker.register("sw.js").then(function () {
            // Drain any backlog left from a previous session right away.
            kickRevokeRetry();
            global.addEventListener("online", kickRevokeRetry);
        }).catch(function () { /* SW unavailable (file:// , no-HTTPS) → fail-soft */ });
    }

    function kickRevokeRetry() {
        if (!("serviceWorker" in navigator)) return;
        navigator.serviceWorker.ready.then(function (reg) {
            // Prefer Background Sync — durable across page close.
            if (reg.sync && typeof reg.sync.register === "function") {
                reg.sync.register(REVOKE_SYNC_TAG).catch(function () {});
            }
            // Always also poke the active worker for an immediate drain.
            if (reg.active) reg.active.postMessage({ type: "retry-revokes" });
        }).catch(function () {});
    }

    // Server-side revoke + localStorage clear. Idempotent: if no live session
    // is stored, just clears localStorage and returns. If the canister call
    // fails (network, expired session, bad token), the local copy is still
    // cleared — leaving the UI signed out — and the revoke is durably queued
    // (P1.1.6) so the Service Worker retries it until the canister confirms or
    // the token naturally expires.
    //
    // Mirrors canisters/memphis/src/lib.rs:end_session, which is itself
    // idempotent against unknown tokens (so re-issuing signOut is safe).
    async function signOut() {
        const s = loadSession();
        clearSession();
        if (!s || !s.session_token_hex) return { ok: true, revoked: false };
        const tokenBytes = hexToBytes(s.session_token_hex);
        const argHex = bytesToHex(encBlob(tokenBytes));
        // Queue BEFORE the network call — survives a page-close mid-revoke.
        await queueRevoke(s.session_token_hex, argHex, s.expires_at_ns);
        try {
            const reply = await memphisCallAwait("end_session", encBlob(tokenBytes));
            const dec = decodeResultEmpty(reply);
            if (dec.err) { kickRevokeRetry(); return { ok: false, revoked: false, err: dec.err }; }
            await dequeueRevoke(s.session_token_hex); // confirmed → drop from queue
            return { ok: true, revoked: true };
        } catch (e) {
            kickRevokeRetry(); // leave queued; the Service Worker retries
            return { ok: false, revoked: false, err: { name: "NetworkError", message: String(e && e.message || e) } };
        }
    }

    global.MemphisPasskey = {
        register,
        signIn,
        signInOrRegister,
        lookupAnchor,
        lookupName: lookupNameToPrincipal,
        nameForPrincipal,
        loadSession,
        saveSession,
        clearSession,
        signOut,
        registerRevokeWorker,
        validateName,
        // Lower-level helpers, exposed for diagnostics.
        _memphisCallAwait: memphisCallAwait,
        _memphisQuery: memphisQuery,
        _bytesToHex: bytesToHex,
    };
})(window);
