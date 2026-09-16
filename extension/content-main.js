// Runs in the page's MAIN world on allowlisted origins. Takes over WebAuthn
// (navigator.credentials.get/create) and forwards requests to passkeyd via the
// isolated content script -> service worker -> native messaging host.
// Anything passkeyd doesn't handle falls through to whatever wrapper (e.g. a
// password manager's) or native implementation sits underneath us.
(() => {
  // Password managers (Elpass/1Password) also hijack WebAuthn in the MAIN
  // world — some define non-configurable own properties on the
  // navigator.credentials instance before we run, which we can neither
  // redefine nor reliably out-race. So we replace navigator.credentials
  // itself: the `credentials` accessor on Navigator is still configurable,
  // and the pristine native methods remain reachable via
  // CredentialsContainer.prototype regardless of instance-level patches.
  const realContainer = navigator.credentials;
  const NATIVE = {
    get: CredentialsContainer.prototype.get.bind(realContainer),
    create: CredentialsContainer.prototype.create.bind(realContainer),
  };
  // Fallback chain: whatever was visible when we ran (possibly a manager's
  // wrapper, so its UI still works for its own credentials); later assignments
  // to our container's get/create are absorbed here too.
  const ORIG = {
    get: realContainer.get.bind(realContainer),
    create: realContainer.create.bind(realContainer),
  };
  // Two guard windows, kept separate on purpose:
  // - forwarding*: we are awaiting ORIG for a modal WebAuthn request; a
  //   wrapper in that chain may fall back into us (e.g. via a live
  //   navigator.credentials reference), and such re-entrant calls go straight
  //   to NATIVE so mutually-fallback wrappers can't recurse.
  // - intercepting*: a modal request is inside passkeyd (has-check or
  //   approval). A second modal request arriving now is genuinely new, not
  //   recursion — it must fail the way the native stack fails overlapping
  //   requests, never fall through to NATIVE, which would pop the platform
  //   (iCloud Keychain) sheet next to our approval prompt.
  let forwardingGet = false;
  let forwardingCreate = false;
  let interceptingGet = false;
  let interceptingCreate = false;

  const pending = new Map();
  let seq = 0;
  // Registrations are only captured while the popup toggle is on, so a normal
  // browser/iCloud passkey enrollment on an allowlisted site stays possible.
  let config = { captureCreate: false };

  window.addEventListener("message", (ev) => {
    if (ev.source !== window || !ev.data) return;
    if (ev.data.__passkeyd_config) {
      config = ev.data.__passkeyd_config;
      return;
    }
    const resp = ev.data.__passkeyd_resp;
    if (!resp) return;
    const p = pending.get(resp.reqId);
    if (p) {
      pending.delete(resp.reqId);
      p(resp);
    }
  });

  function call(payload) {
    return new Promise((resolve) => {
      const reqId = ++seq;
      pending.set(reqId, resolve);
      window.postMessage({ __passkeyd_req: { reqId, ...payload } }, window.origin);
      setTimeout(() => {
        if (pending.has(reqId)) {
          pending.delete(reqId);
          resolve({ ok: false, error: "passkeyd timeout" });
        }
      }, 180000);
    });
  }

  // WebAuthn callers cancel via AbortSignal (Okta does when the user switches
  // authenticators). Reject as soon as the signal fires so the intercept
  // window frees up for the caller's next request; the daemon side of an
  // in-flight approval runs to its own timeout.
  function abortable(promise, signal) {
    if (!signal) return promise;
    return new Promise((resolve, reject) => {
      const onAbort = () =>
        reject(signal.reason || new DOMException("The operation was aborted.", "AbortError"));
      if (signal.aborted) return onAbort();
      signal.addEventListener("abort", onAbort, { once: true });
      promise.then(
        (v) => { signal.removeEventListener("abort", onAbort); resolve(v); },
        (e) => { signal.removeEventListener("abort", onAbort); reject(e); },
      );
    });
  }

  const enc = new TextEncoder();
  const b64u = (buf) =>
    btoa(String.fromCharCode(...new Uint8Array(buf)))
      .replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
  const fromB64u = (s) => {
    const t = s.replaceAll("-", "+").replaceAll("_", "/")
      .padEnd(Math.ceil(s.length / 4) * 4, "=");
    return Uint8Array.from(atob(t), (c) => c.charCodeAt(0)).buffer;
  };
  const bufSrc = (v) =>
    v instanceof ArrayBuffer ? v : v.buffer.slice(v.byteOffset, v.byteOffset + v.byteLength);

  async function clientData(type, challenge) {
    const json = JSON.stringify({
      type,
      challenge: b64u(bufSrc(challenge)),
      origin: window.origin,
      crossOrigin: false,
    });
    const bytes = enc.encode(json).buffer;
    const hash = await crypto.subtle.digest("SHA-256", bytes);
    return { bytes, hash: b64u(hash) };
  }

  function fabricate(idB64u, response, isCreate) {
    const cred = {
      id: idB64u,
      rawId: fromB64u(idB64u),
      type: "public-key",
      authenticatorAttachment: "cross-platform",
      response,
      getClientExtensionResults: () => ({}),
      toJSON() {
        const r = isCreate
          ? {
              clientDataJSON: b64u(response.clientDataJSON),
              attestationObject: b64u(response.attestationObject),
              authenticatorData: b64u(response.getAuthenticatorData()),
              publicKey: b64u(response.getPublicKey()),
              publicKeyAlgorithm: response.getPublicKeyAlgorithm(),
              transports: response.getTransports(),
            }
          : {
              clientDataJSON: b64u(response.clientDataJSON),
              authenticatorData: b64u(response.authenticatorData),
              signature: b64u(response.signature),
              userHandle: response.userHandle ? b64u(response.userHandle) : null,
            };
        return {
          id: idB64u,
          rawId: idB64u,
          type: "public-key",
          authenticatorAttachment: "cross-platform",
          clientExtensionResults: {},
          response: r,
        };
      },
    };
    try {
      Object.setPrototypeOf(cred, PublicKeyCredential.prototype);
    } catch {}
    return cred;
  }

  const wrappedGet = async function (options) {
    if (forwardingGet) return NATIVE.get(options);
    const pk = options && options.publicKey;
    // Conditional-mediation requests fire automatically on page load and stay
    // pending until the page aborts them; non-WebAuthn requests aren't ours
    // either. Both pass through unguarded — no flag may span their open-ended
    // lifetime, or every later modal request would be diverted.
    if (!pk || (options && options.mediation === "conditional")) return ORIG.get(options);
    if (interceptingGet) {
      throw new DOMException("A request is already pending.", "NotAllowedError");
    }
    const signal = options.signal;
    if (signal && signal.aborted) {
      throw signal.reason || new DOMException("The operation was aborted.", "AbortError");
    }
    interceptingGet = true;
    try {
      const rpId = pk.rpId || location.hostname;
      const allow = (pk.allowCredentials || []).map((c) => b64u(bufSrc(c.id)));
      const has = await abortable(call({ op: "has", rpId, origin: window.origin, allow }), signal);
      if (has.ok && has.has) {
        const cd = await clientData("webauthn.get", pk.challenge);
        const resp = await abortable(call({
          op: "get", rpId, origin: window.origin, clientDataHash: cd.hash, allow,
        }), signal);
        if (!resp.ok) {
          throw new DOMException(resp.error || "passkeyd: not approved", "NotAllowedError");
        }
        return fabricate(resp.id, {
          clientDataJSON: cd.bytes,
          authenticatorData: fromB64u(resp.authenticatorData),
          signature: fromB64u(resp.signature),
          userHandle: resp.userHandle ? fromB64u(resp.userHandle) : null,
        }, false);
      }
    } finally {
      interceptingGet = false;
    }
    // passkeyd doesn't have this credential: fall through to the ORIG chain,
    // guarded against wrapper recursion.
    forwardingGet = true;
    try {
      return await ORIG.get(options);
    } finally {
      forwardingGet = false;
    }
  };

  const wrappedCreate = async function (options) {
    if (forwardingCreate) return NATIVE.create(options);
    const pk = options && options.publicKey;
    if (!pk) return ORIG.create(options);
    if (!config.captureCreate) {
      // Normal browser/iCloud enrollment path: forward, guarded against
      // wrapper recursion (bounded by the native sheet, unlike conditional).
      forwardingCreate = true;
      try {
        return await ORIG.create(options);
      } finally {
        forwardingCreate = false;
      }
    }
    if (interceptingCreate) {
      throw new DOMException("A request is already pending.", "NotAllowedError");
    }
    const signal = options.signal;
    if (signal && signal.aborted) {
      throw signal.reason || new DOMException("The operation was aborted.", "AbortError");
    }
    interceptingCreate = true;
    try {
      const rpId = (pk.rp && pk.rp.id) || location.hostname;
      const cd = await clientData("webauthn.create", pk.challenge);
      const resp = await abortable(call({
        op: "create",
        rpId,
        origin: window.origin,
        clientDataHash: cd.hash,
        user: {
          id: b64u(bufSrc(pk.user.id)),
          name: pk.user.name || "",
          displayName: pk.user.displayName || "",
        },
        algs: (pk.pubKeyCredParams || []).map((p) => p.alg),
        excludeIds: (pk.excludeCredentials || []).map((c) => b64u(bufSrc(c.id))),
      }), signal);
      if (!resp.ok) {
        throw new DOMException(resp.error || "passkeyd: not approved", "NotAllowedError");
      }
      const authData = fromB64u(resp.authenticatorData);
      const spki = fromB64u(resp.publicKey);
      return fabricate(resp.id, {
        clientDataJSON: cd.bytes,
        attestationObject: fromB64u(resp.attestationObject),
        getAuthenticatorData: () => authData,
        getPublicKey: () => spki,
        getPublicKeyAlgorithm: () => resp.publicKeyAlgorithm,
        getTransports: () => ["hybrid"],
      }, true);
    } finally {
      interceptingCreate = false;
    }
  };

  // Our replacement container: behaves like CredentialsContainer, but
  // get/create are non-configurable accessors that always yield our wrappers
  // and absorb later assignments (another manager wrapping "us") into ORIG.
  const container = Object.create(CredentialsContainer.prototype);
  for (const m of ["store", "preventSilentAccess"]) {
    if (typeof realContainer[m] === "function") {
      Object.defineProperty(container, m, {
        value: (...a) => CredentialsContainer.prototype[m].apply(realContainer, a),
      });
    }
  }
  function expose(name, wrapper) {
    Object.defineProperty(container, name, {
      configurable: false,
      enumerable: true,
      get: () => wrapper,
      set: (v) => {
        if (typeof v === "function" && v !== wrapper) {
          ORIG[name] = (o) => v.call(container, o);
        }
      },
    });
  }
  expose("get", wrappedGet);
  expose("create", wrappedCreate);

  try {
    Object.defineProperty(navigator, "credentials", {
      configurable: false,
      enumerable: true,
      get: () => container,
    });
  } catch (e) {
    // navigator.credentials itself already locked by someone else: last
    // resort is plain assignment on the real container (works when their
    // property is writable or an absorbing accessor).
    try {
      realContainer.get = wrappedGet;
      realContainer.create = wrappedCreate;
    } catch {}
    console.warn("passkeyd: could not install WebAuthn hook cleanly:", e);
  }
})();
