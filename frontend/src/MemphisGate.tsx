/**
 * MemphisGate — the sign-in strip for a Memphis-authenticated app.
 *
 * Signed out: a name field plus a "Sign in with passkey" button. The
 * same control registers a new name or signs into an existing one —
 * Memphis decides by looking the name up first.
 *
 * Signed in: the identity and a sign-out button.
 */
import { useState } from "react";
import type { MemphisAuth } from "./useMemphis";

export default function MemphisGate({ auth }: { auth: MemphisAuth }) {
  const [name, setName] = useState("");

  if (auth.signedIn) {
    return (
      <section className="panel memphis">
        <h2>Identity — Memphis passkey</h2>
        <p className="who">
          signed in as <strong>{auth.displayName}</strong>
          {auth.session?.display_tag && (
            <span className="tag"> #{auth.session.display_tag}</span>
          )}
        </p>
        <button onClick={() => void auth.signOut()} disabled={auth.busy}>
          {auth.busy ? "signing out…" : "Sign out"}
        </button>
      </section>
    );
  }

  // A name with no identity yet is not an error — confirm, then register.
  // The two steps exist so a mistyped name cannot silently mint a second
  // identity (and a second passkey) for you.
  if (auth.pendingCreate) {
    return (
      <section className="panel memphis">
        <h2>Identity — Memphis passkey</h2>
        <p className="who">
          No identity exists for <strong>{auth.pendingCreate}</strong> yet.
        </p>
        <div className="row">
          <button onClick={() => void auth.confirmCreate()} disabled={auth.busy}>
            {auth.busy ? "waiting for passkey…" : "Create it with a passkey"}
          </button>
          <button
            className="secondary"
            onClick={auth.cancelCreate}
            disabled={auth.busy}
          >
            Use a different name
          </button>
        </div>
        {auth.error && <p className="error">{auth.error}</p>}
        <p className="hint">
          Creating registers a passkey on this device and claims the name
          on-chain.
        </p>
      </section>
    );
  }

  return (
    <section className="panel memphis">
      <h2>Identity — Memphis passkey</h2>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          const n = name.trim();
          if (!n) return;
          // The client requires the `.thebes` suffix; append it rather than
          // making the user learn that from a thrown error.
          const full = n.endsWith(".thebes") ? n : `${n}.thebes`;
          void auth.signIn(full).catch(() => {});
        }}
      >
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="yourname.thebes"
          aria-label="Memphis name"
          autoComplete="username webauthn"
        />
        <button type="submit" disabled={auth.busy || !name.trim()}>
          {auth.busy ? "checking…" : "Sign in with passkey"}
        </button>
      </form>
      {auth.error && <p className="error">{auth.error}</p>}
      <p className="hint">
        Names end in <code>.thebes</code> (added for you) with a 3–32
        character stem of <code>a-z 0-9 -</code>. An existing name signs in;
        a new one asks before registering. Requires the app to be served
        from the gateway — passkeys do not work on localhost.
      </p>
    </section>
  );
}
