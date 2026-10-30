import { discoverLinkRelay, createDeviceLinkReceiver, sendDeviceLink,
  requestOriginMigration, serveOriginMigration } from "./device-link.mjs";
import { createEmailGate } from "./email-gate-client.mjs";

export function continuityUI({ keys, credit, cfg, api, error, beforeExport }) {
  const $ = (id) => document.getElementById(id);
  let receiver, emailRequest, emailPurpose, dkimRequest, dkimPoll;
  const status = (text) => { $("continuity-status").textContent = text; };
  const onCode = (code) => { $("continuity-panel").hidden = false; $("link-code").textContent = code; };
  const confirm = async (code) => {
    onCode(code);
    $("link-confirm").hidden = false;
    return new Promise((resolve) => {
      $("link-approve").onclick = () => { $("link-confirm").hidden = true; resolve(true); };
      $("link-deny").onclick = () => { $("link-confirm").hidden = true; resolve(false); };
    });
  };
  const imported = async (bundle) => {
    await keys.import(bundle);
    status("Device linked. Loading your chats…");
  };
  const bind = (id, fn) => { $(id).onclick = async () => {
    $(id).disabled = true;
    try { await fn(); } catch (e) { status(e.message); error(e); }
    finally { $(id).disabled = false; }
  }; };
  bind("use-another-device", async () => {
    $("continuity-panel").hidden = !$("continuity-panel").hidden;
  });
  bind("add-passkey", async () => {
    await keys.addPasskey({ credit, api });
    status("Passkey saved. Use Recover with passkey on your other device.");
  });
  bind("recover-passkey", async () => {
    await keys.recoverPasskey({ api });
    location.reload();
  });
  const emailGate = createEmailGate({ base: "", policy: cfg.emailGate });
  const requestDkim = async (purpose) => {
    dkimPoll?.abort();
    dkimPoll = undefined;
    dkimRequest = undefined;
    $("send-recovery-email").hidden = true;
    status("Verifying the recovery gate’s attestation…");
    if (purpose === "enroll") await beforeExport();
    dkimRequest = await emailGate.requestDkim($("recovery-email").value, purpose);
    $("send-recovery-email").href = dkimRequest.mailto;
    $("send-recovery-email").hidden = false;
    status("Send the prepared message from " + dkimRequest.email + ". This page will wait for it.");
  };
  bind("enroll-email", () => requestDkim("enroll"));
  bind("request-email", () => requestDkim("recover"));
  $("send-recovery-email").onclick = () => {
    if (!dkimRequest || dkimPoll) return;
    const request = dkimRequest;
    dkimPoll = new AbortController();
    const poll = dkimPoll;
    status("Waiting for your recovery email…");
    (async () => {
      const headers = await emailGate.waitDkim(request, { signal: poll.signal });
      status("Checking your email signature in the attested gate…");
      const result = await emailGate.confirmDkim(request, headers,
        request.purpose === "enroll" ? keys.bundle : undefined);
      if (request.purpose === "enroll") {
        dkimRequest = undefined;
        $("send-recovery-email").hidden = true;
        status("Recovery email added. Use Recover with email on another device.");
      } else {
        await imported(result);
        location.reload();
      }
    })().catch((e) => {
      if (e.name !== "AbortError") { status(e.message); error(e); }
    }).finally(() => { if (dkimPoll === poll) dkimPoll = undefined; });
  };
  const requestEmail = async (purpose) => {
    emailPurpose = purpose;
    status("Verifying the recovery gate’s attestation…");
    emailRequest = await emailGate.request($("recovery-email").value.trim(), purpose);
    status("Enter the email code sent to your address.");
  };
  bind("enroll-email-smtp", () => requestEmail("enroll"));
  bind("request-email-smtp", () => requestEmail("recover"));
  bind("confirm-email", async () => {
    if (!emailRequest) throw Error("Request an email code first.");
    const result = await emailGate.confirm(emailRequest, $("recovery-code").value.trim(),
      emailPurpose === "enroll" ? keys.bundle : undefined);
    if (emailPurpose === "enroll") {
      emailRequest = undefined;
      status("Recovery email added. Use Recover by email on another device.");
    } else {
      await imported(result);
      location.reload();
    }
  });
  bind("receive-device", async () => {
    await receiver?.close();
    receiver = await createDeviceLinkReceiver({ relayAddress: await discoverLinkRelay(cfg.tunnels),
      onCode, onStatus: status, confirm, onBundle: imported });
    $("link-qr").src = receiver.qrDataUrl;
    $("link-qr").hidden = false;
    $("link-qr-text").value = receiver.qr;
    $("link-qr-text").hidden = false;
    receiver.completed.then(() => location.reload()).catch((e) => { status(e.message); error(e); });
    status("Scan this QR with the device that has your chats, then compare the code.");
  });
  bind("send-device", async () => {
    await beforeExport();
    await sendDeviceLink($("link-target").value, keys.bundle, { onCode, confirm, onStatus: status });
    status("Device linked. Both devices now have your wallet and chats.");
  });
  bind("scan-device", async () => {
    if (!globalThis.BarcodeDetector) throw Error("QR scanning is unavailable in this browser. Paste the QR link from the other device.");
    const detector = new BarcodeDetector({ formats: ["qr_code"] });
    const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
    const video = $("link-camera");
    video.srcObject = stream; video.hidden = false;
    try {
      await video.play();
      const until = Date.now() + 60000;
      while (Date.now() < until) {
        const found = await detector.detect(video);
        if (found.length) { $("link-target").value = found[0].rawValue; status("QR scanned. Choose Link this device."); return; }
        await new Promise((r) => setTimeout(r, 150));
      }
      throw Error("No QR found. Try scanning again.");
    } finally { stream.getTracks().forEach((t) => t.stop()); video.hidden = true; video.srcObject = null; }
  });
  bind("migrate-origin", async () => {
    const bundle = await requestOriginMigration($("old-origin").value, { confirm, onCode, onStatus: status });
    await imported(bundle);
    location.reload();
  });
  serveOriginMigration({ getBundle: async () => { await beforeExport(); return keys.bundle; }, confirm, onCode, onStatus: status,
    allowedOrigin: "https://private-agent.dstack.soc1024.com" }).catch((e) => { status(e.message); error(e); });
  window.addEventListener("pagehide", () => { receiver?.close(); dkimPoll?.abort(); }, { once: true });
  return { bind, status };
}
