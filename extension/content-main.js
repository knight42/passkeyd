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
  // Reentrancy guards: a wrapper in the ORIG chain may fall back into us
  // (e.g. via a live navigator.credentials reference); nested calls go
  // straight to NATIVE so mutually-fallback wrappers can't recurse.
  let inGet = false;
  let inCreate = false;

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
    if (inGet) return NATIVE.get(options);
    inGet = true;
    try {
      const pk = options && options.publicKey;
      // Conditional-mediation requests fire automatically on page load; leave them alone.
      if (!pk || (options && options.mediation === "conditional")) return ORIG.get(options);
      const rpId = pk.rpId || location.hostname;
      const allow = (pk.allowCredentials || []).map((c) => b64u(bufSrc(c.id)));
      const has = await call({ op: "has", rpId, origin: window.origin, allow });
      if (!has.ok || !has.has) return ORIG.get(options);

      const cd = await clientData("webauthn.get", pk.challenge);
      const resp = await call({
        op: "get", rpId, origin: window.origin, clientDataHash: cd.hash, allow,
      });
      if (!resp.ok) {
        throw new DOMException(resp.error || "passkeyd: not approved", "NotAllowedError");
      }
      return fabricate(resp.id, {
        clientDataJSON: cd.bytes,
        authenticatorData: fromB64u(resp.authenticatorData),
        signature: fromB64u(resp.signature),
        userHandle: resp.userHandle ? fromB64u(resp.userHandle) : null,
      }, false);
    } finally {
      inGet = false;
    }
  };

  const wrappedCreate = async function (options) {
    if (inCreate) return NATIVE.create(options);
    inCreate = true;
    try {
      const pk = options && options.publicKey;
      if (!pk || !config.captureCreate) return ORIG.create(options);
      const rpId = (pk.rp && pk.rp.id) || location.hostname;
      const cd = await clientData("webauthn.create", pk.challenge);
      const resp = await call({
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
      });
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
      inCreate = false;
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
