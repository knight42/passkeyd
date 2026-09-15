// Bridges extension messages to the passkeyd native messaging host.
const HOST = "com.zack.passkeyd";

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || msg.type !== "passkeyd") return;
  const port = chrome.runtime.connectNative(HOST);
  let done = false;
  port.onMessage.addListener((resp) => {
    if (resp && resp.type === "ping") return; // host keepalive, resets SW idle timer
    done = true;
    sendResponse(resp);
    port.disconnect();
  });
  port.onDisconnect.addListener(() => {
    if (!done) {
      sendResponse({
        ok: false,
        error: chrome.runtime.lastError
          ? chrome.runtime.lastError.message
          : "passkeyd host disconnected",
      });
    }
  });
  port.postMessage(msg.payload);
  return true; // keep sendResponse alive for the async reply
});
