// Isolated-world relay between the MAIN-world shim and the service worker.
chrome.storage.local.get({ captureCreate: false }).then((cfg) => {
  window.postMessage({ __passkeyd_config: cfg }, window.origin);
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.captureCreate) {
    window.postMessage(
      { __passkeyd_config: { captureCreate: changes.captureCreate.newValue } },
      window.origin,
    );
  }
});

window.addEventListener("message", (ev) => {
  if (ev.source !== window || !ev.data) return;
  const req = ev.data.__passkeyd_req;
  if (!req) return;
  chrome.runtime.sendMessage({ type: "passkeyd", payload: req }).then(
    (resp) =>
      window.postMessage(
        { __passkeyd_resp: { ...(resp || { ok: false, error: "no response from host" }), reqId: req.reqId } },
        window.origin,
      ),
    (e) =>
      window.postMessage(
        { __passkeyd_resp: { reqId: req.reqId, ok: false, error: String(e) } },
        window.origin,
      ),
  );
});
