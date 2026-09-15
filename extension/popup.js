const el = document.getElementById("cap");
chrome.storage.local.get({ captureCreate: false }).then((c) => {
  el.checked = c.captureCreate;
  el.addEventListener("change", () => chrome.storage.local.set({ captureCreate: el.checked }));
});
