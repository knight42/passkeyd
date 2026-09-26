// The page is an untrusted WebAuthn client. Only this extension-world bridge
// may choose the origin or construct clientDataJSON/clientDataHash.
const HOST = "com.zack.passkeyd";

const b64u = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)))
  .replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");

async function prepareRequest(payload, sender) {
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

function callHost(request) {
  return new Promise((resolve) => {
    const port = chrome.runtime.connectNative(HOST);
    let done = false;
    port.onMessage.addListener((resp) => {
      if (resp && resp.type === "ping") return;
      done = true;
      resolve(resp);
      port.disconnect();
    });
    port.onDisconnect.addListener(() => {
      if (!done) resolve({
        ok: false,
        error: chrome.runtime.lastError
          ? chrome.runtime.lastError.message
          : "passkeyd host disconnected",
      });
    });
    port.postMessage(request);
  });
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || msg.type !== "passkeyd") return;
  (async () => {
    try {
      const { request, clientDataJSON } = await prepareRequest(msg.payload, sender);
      const response = await callHost(request);
      sendResponse(clientDataJSON ? { ...response, clientDataJSON } : response);
    } catch (e) {
      sendResponse({ ok: false, error: String(e) });
    }
  })();
  return true; // keep sendResponse alive for validation and the native reply
});
