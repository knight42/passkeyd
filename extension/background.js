// The page is an untrusted WebAuthn client. Only this extension-world bridge
// may choose the origin or construct clientDataJSON/clientDataHash.
const HOST = "com.zack.passkeyd";

const b64u = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)))
  .replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");

function trustedOrigin(sender) {
  // Content scripts currently run only in top-level documents. Reject opaque
  // origins, extension pages and frames instead of inventing crossOrigin data.
  if (sender.id !== chrome.runtime.id || !sender.tab || sender.frameId !== 0 ||
      !sender.origin || sender.origin === "null") {
    throw new Error("untrusted request context");
  }
  const url = new URL(sender.origin);
  if (url.origin !== sender.origin || new URL(sender.url).origin !== sender.origin ||
      !(url.protocol === "https:" || (url.protocol === "http:" && url.hostname === "localhost"))) {
    throw new Error("untrusted request origin");
  }
  return url;
}

async function prepareRequest(payload, sender) {
  const url = trustedOrigin(sender);
  if (!payload || !["has", "get", "create"].includes(payload.op)) {
    throw new Error("unknown operation");
  }
  const rpId = typeof payload.rpId === "string" ? payload.rpId.toLowerCase() : "";
  if (!rpId || !(rpId.includes(".") || rpId === "localhost") ||
      !(url.hostname === rpId || url.hostname.endsWith("." + rpId))) {
    throw new Error("RP ID does not match the requesting origin");
  }
  // Explicit fields: never forward page-supplied origin, client data or hashes.
  const request = { op: payload.op, rpId, origin: url.origin };
  if (payload.op === "has" || payload.op === "get") request.allow = payload.allow;
  if (payload.op === "has") return { request };
  if (payload.op === "create") {
    const cfg = await chrome.storage.local.get({ captureCreate: false });
    if (cfg.captureCreate !== true) throw new Error("registration capture is disabled");
    request.user = payload.user;
    request.algs = payload.algs;
    request.excludeIds = payload.excludeIds;
  }
  const challenge = payload.challenge;
  if (typeof challenge !== "string" || !/^[A-Za-z0-9_-]*$/.test(challenge) ||
      challenge.length % 4 === 1) {
    throw new Error("invalid challenge");
  }
  const decoded = Uint8Array.from(atob(challenge.replaceAll("-", "+").replaceAll("_", "/")),
    (c) => c.charCodeAt(0));
  if (b64u(decoded) !== challenge) throw new Error("noncanonical challenge");
  const bytes = new TextEncoder().encode(JSON.stringify({
    type: payload.op === "get" ? "webauthn.get" : "webauthn.create",
    challenge,
    origin: url.origin,
    crossOrigin: false,
  }));
  request.clientDataHash = b64u(await crypto.subtle.digest("SHA-256", bytes));
  return { request, clientDataJSON: b64u(bytes) };
}

// No page-controlled queue: at most one request per origin and four overall.
// Reserve synchronously before any await, including client-data hashing.
const activeOrigins = new Set();
let budgetUpdate = Promise.resolve();
function takeBudget(origin) {
  const result = budgetUpdate.then(async () => {
    // session survives MV3 worker restarts without persisting browsing history
    // across browser sessions. Serialize updates across concurrent origins.
    const { nativeRequestTimes = {} } = await chrome.storage.session.get("nativeRequestTimes");
    const cutoff = Date.now() - 60000;
    const times = Object.fromEntries(Object.entries(nativeRequestTimes)
      .map(([key, stamps]) => [key, stamps.filter((stamp) => stamp > cutoff)])
      .filter(([, stamps]) => stamps.length));
    const stamps = times[origin] || [];
    if (stamps.length >= 20) throw Object.assign(new Error("request rate limit exceeded"), { code: "rate_limited" });
    stamps.push(Date.now());
    times[origin] = stamps;
    await chrome.storage.session.set({ nativeRequestTimes: times });
  });
  budgetUpdate = result.catch(() => {});
  return result;
}

function callHost(request) {
  return new Promise((resolve) => {
    const port = chrome.runtime.connectNative(HOST);
    let done = false;
    const finish = (response) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve(response);
      port.disconnect();
    };
    // Match the MAIN shim's request lifetime, even if a host keeps pinging.
    const timer = setTimeout(() => finish({ ok: false, error: "passkeyd timeout" }), 180000);
    port.onMessage.addListener((resp) => {
      if (resp && resp.type === "ping") return;
      finish(resp);
    });
    port.onDisconnect.addListener(() => finish({
      ok: false,
      error: chrome.runtime.lastError ? chrome.runtime.lastError.message : "passkeyd host disconnected",
    }));
    try { port.postMessage(request); }
    catch (e) { finish({ ok: false, error: String(e) }); }
  });
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || msg.type !== "passkeyd") return;
  let origin;
  try {
    origin = trustedOrigin(sender).origin;
    if (activeOrigins.has(origin) || activeOrigins.size >= 4) {
      sendResponse({ ok: false, error: "passkeyd is busy; retry later", errorCode: "busy" });
      return;
    }
    activeOrigins.add(origin);
  } catch (e) {
    sendResponse({ ok: false, error: String(e) });
    return;
  }
  (async () => {
    let response;
    try {
      const { request, clientDataJSON } = await prepareRequest(msg.payload, sender);
      await takeBudget(origin);
      const result = await callHost(request);
      response = clientDataJSON ? { ...result, clientDataJSON } : result;
    } catch (e) {
      response = { ok: false, error: String(e), errorCode: e.code };
    } finally {
      activeOrigins.delete(origin);
    }
    // Release before replying: a successful has immediately triggers get.
    sendResponse(response);
  })();
  return true;
});
