/**
 * useMemphis — Memphis passkey sign-in, over the proven
 * `window.MemphisPasskey` client (the vendored `passkey.js` loaded by a
 * script tag in index.html).
 *
 * Memphis is Thebes' identity layer — the substrate's Internet Identity
 * equivalent — living at canister 921. A passkey (WebAuthn) sign-in
 * yields a session with a stable anchor id and a display tag; the client
 * persists it in localStorage, so a refresh keeps you signed in.
 *
 * NOTE ON LOCAL DEV: passkey.js pins the WebAuthn relying-party id to
 * `memphis.mercaturaforum.com`, so sign-in only works when the page is
 * served from that origin (i.e. after `thebes-deploy deploy`, at
 * /_/raw/<cid>/index.html). On localhost the browser refuses the
 * credential — the rest of the app still works.
 */
import { useCallback, useEffect, useState } from "react";

export interface MemphisSession {
  name: string;
  anchor_id_hex: string;
  session_token_hex: string;
  expires_at_ns: number;
  display_tag: string;
}

type Passkey = {
  // `confirmCreate: true` is REQUIRED to register a name that does not
  // exist yet — without it the client throws `NameNotRegistered` rather
  // than silently minting an identity for a typo. That guard is why this
  // hook exposes a two-step create flow instead of one call.
  signInOrRegister: (
    name: string,
    opts?: { confirmCreate?: boolean }
  ) => Promise<MemphisSession>;
  loadSession: () => MemphisSession | null;
  signOut: () => Promise<void>;
};

function pk(): Passkey {
  const p = (window as unknown as { MemphisPasskey?: Passkey }).MemphisPasskey;
  if (!p) {
    throw new Error(
      "passkey.js not loaded — check the <script src=\"./passkey.js\"> tag in index.html"
    );
  }
  return p;
}

export interface MemphisAuth {
  session: MemphisSession | null;
  signedIn: boolean;
  /** Short human label for the signed-in identity. */
  displayName: string;
  /** Sign in. An unregistered name sets `pendingCreate` instead of erroring. */
  signIn: (name: string) => Promise<void>;
  /**
   * Name awaiting create confirmation — set when `signIn` found no
   * identity for it. Show a confirm affordance and call `confirmCreate`.
   */
  pendingCreate: string | null;
  /** Register the `pendingCreate` name (prompts for a passkey). */
  confirmCreate: () => Promise<void>;
  /** Abandon the pending create. */
  cancelCreate: () => void;
  signOut: () => Promise<void>;
  busy: boolean;
  error: string | undefined;
}

export function useMemphis(): MemphisAuth {
  const [session, setSession] = useState<MemphisSession | null>(null);
  const [pendingCreate, setPendingCreate] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  // Restore an existing session on mount.
  useEffect(() => {
    try {
      setSession(pk().loadSession());
    } catch {
      /* passkey.js not present yet — leave signed out */
    }
  }, []);

  const signIn = useCallback(async (name: string) => {
    setBusy(true);
    setError(undefined);
    setPendingCreate(null);
    try {
      // Existing name → WebAuthn assertion. Unregistered name → the client
      // throws `NameNotRegistered` on purpose, so a typo cannot silently
      // create a second identity. Surface it as a confirmable intent.
      setSession(await pk().signInOrRegister(name));
    } catch (e) {
      const code = (e as { code?: string })?.code;
      const requested = (e as { nameRequested?: string })?.nameRequested;
      if (code === "NameNotRegistered") {
        setPendingCreate(requested || name);
        return; // not an error — awaiting confirmation
      }
      setError(e instanceof Error ? e.message : String(e));
      throw e;
    } finally {
      setBusy(false);
    }
  }, []);

  const confirmCreate = useCallback(async () => {
    const name = pendingCreate;
    if (!name) return;
    setBusy(true);
    setError(undefined);
    try {
      setSession(await pk().signInOrRegister(name, { confirmCreate: true }));
      setPendingCreate(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }, [pendingCreate]);

  const cancelCreate = useCallback(() => {
    setPendingCreate(null);
    setError(undefined);
  }, []);

  const signOut = useCallback(async () => {
    setBusy(true);
    try {
      await pk().signOut(); // revokes the session on-canister, best effort
    } catch {
      /* best-effort; clear locally regardless */
    } finally {
      setSession(null);
      setBusy(false);
    }
  }, []);

  return {
    session,
    signedIn: !!session,
    displayName: session?.name || session?.display_tag || "",
    signIn,
    pendingCreate,
    confirmCreate,
    cancelCreate,
    signOut,
    busy,
    error,
  };
}
