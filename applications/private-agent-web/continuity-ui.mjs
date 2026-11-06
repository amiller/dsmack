import { store } from "./credit.mjs";
import { discoverLinkRelay, createDeviceLinkReceiver, sendDeviceLink,
  requestOriginMigration, serveOriginMigration } from "./device-link.mjs";
import { watchRecovery } from "./recovery-notice.mjs";
import { createEmailGate } from "./email-gate-client.mjs";

export function recoveryMessage(e) {
  const message = String(e?.message || "");
  if (e?.code === 'RECOVERY_NOT_AUTHORIZED' || e?.code === 'RECOVERY_CHAIN_UNAVAILABLE') return message;
  if (e?.status >= 400 && e?.status < 500 && e?.status !== 404) return message;
  if (/^We (?:didn.t receive your email|couldn.t check for your email)/.test(message)) return message;
  if (e?.name === "NotAllowedError" || e?.name === "AbortError") return "That request was cancelled or timed out. Try again when you’re ready.";
  if (e?.name === "NotSupportedError" || /does not support PRF|PRF.*(?:unavailable|unsupported)/i.test(message)) return "This browser or passkey cannot restore these keys. Use the QR link from your original device instead.";
  if (e?.name === "SecurityError" || /Open https:/i.test(message)) return "Open https://private-agent.dstack.soc1024.com to use your passkey, or link from your original device with a QR code.";
  if (e?.name === "InvalidStateError") return "That passkey is already registered. Try Recover with passkey, or choose a different passkey.";
  if (/attestation|measurement|quote|TCB|nonce|approved|policy|digest|event log|bound to/i.test(message)) return "We couldn’t verify the recovery service. Try again later, or link directly from your original device with a QR code.";
  if (/not found|no recovery|not enrolled|unknown email|no record/i.test(message)) return "No recovery method was found. Add a passkey or email on your original browser first, or use its QR link.";
  if (/email address/i.test(message)) return "Enter your email address, then try again.";
  if (/Start fresh|recover your wallet/i.test(message)) return "Choose Start fresh or recover your wallet before adding recovery or linking another device.";
  if (/QR scanning|camera|Permission|NotFoundError/i.test(message + e?.name)) return "The camera is unavailable. Paste the QR link from your other device instead.";
  if (/fetch|network|offline|receiver|configured|connection/i.test(message) || e instanceof TypeError) return "The recovery service couldn’t be reached. Check your connection and try again, or use a QR link from your original device.";
  return "Recovery couldn’t finish. Try again, or link from your original device with a QR code.";
}

export function continuityUI({ keys, credit, cfg, api, error, beforeExport, beforeSwitch }) {
  const $ = (id) => document.getElementById(id);
  let hasValue = false;
  let receiver, dkimPoll;
  const status = (text) => { $("continuity-status").textContent = text; };
  const report = (e) => { status(recoveryMessage(e)); };
  const requireWallet = () => { if (!keys.bundle) throw Error("Choose Start fresh or recover your wallet first."); };
  const update = async (state = {}) => {
    if (state.hasValue !== undefined) hasValue = state.hasValue;
    $("welcome").hidden = !!keys.bundle;
    for (const id of ["add-passkey", "enroll-email", "send-device", "switch-wallet"]) $(id).disabled = !keys.bundle;
    const enrolled = await store("continuity.passkey") || await store("continuity.email");
    $("recovery-nudge").hidden = !keys.bundle || !hasValue || !!enrolled;
  };
  bindWelcome();
  function bindWelcome() {
    $("used-before").onclick = () => {
      $("continuity-panel").hidden = false;
      $("recover-passkey").focus();
    };
  }

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
    if (keys.bundle && keys.bundle.walletKey !== bundle.walletKey) {
      if (!window.confirm("This will replace the wallet loaded on this device with the linked wallet and its chats. Continue?"))
        throw Error("Wallet replacement cancelled.");
      await beforeSwitch();
    }
    await keys.import(bundle);
    await store("continuity.imported", true);
    status("Device linked. Loading your chats…");
  };
  const bind = (id, fn) => { $(id).onclick = async () => {
    $(id).disabled = true;
    try { await fn(); } catch (e) { report(e); }
    finally { $(id).disabled = false; }
  }; };
  bind("use-another-device", async () => {
    $("continuity-panel").hidden = !$("continuity-panel").hidden;
  });
  bind("switch-wallet", async () => {
    requireWallet();
    if (!await store("continuity.passkey") && !await store("continuity.email")) {
      status("Save a passkey or add a recovery email in this panel before switching wallets, so you can return to this wallet.");
      $("add-passkey").focus();
      return;
    }
    if (!window.confirm("Switch wallets on this device? Use your saved passkey or email to return to this wallet.")) return;
    await beforeSwitch();
    await keys.disconnect();
    location.reload();
  });
  bind("add-passkey", async () => {
    requireWallet();
    await beforeExport();
    await keys.addPasskey({ credit, api });
    await update();
    status("Passkey saved. Use Recover with passkey on your other device.");
  });
  bind("recover-passkey", async () => {
    await keys.recoverPasskey({ api });
    location.reload();
  });
  const emailGate = createEmailGate({ base: new URL(".", location.href).pathname.replace(/(?:\/a)?\/$/, ""), policy: cfg.emailGate });
  const stopRecoveryNotice = watchRecovery({ gate: emailGate, getBundle: () => keys.bundle });
  const showPending = (pending) => {
    $("continuity-panel").hidden = false;
    $("finish-email-recovery").hidden = false;
    status("Email recovery is waiting until " + new Date(pending.releaseAt).toLocaleString() +
      ". Return to this browser after 48 hours to recover. Existing devices can cancel it.");
  };
  bind("finish-email-recovery", async () => {
    const pending = await store("continuity.pendingEmail");
    if (!pending) throw Error("No pending email recovery in this browser.");
    try {
      const result = await emailGate.release(pending);
      if (result.pending) { showPending(result); return; }
      await imported(result);
      await store("continuity.pendingEmail", null);
      location.reload();
    } catch (e) {
      if (e.status === 404 || e.status === 410) {
        await store("continuity.pendingEmail", null);
        $("finish-email-recovery").hidden = true;
      }
      throw e;
    }
  });
  store("continuity.pendingEmail").then(pending => {
    if (pending && !keys.bundle) showPending(pending);
  }).catch(report);
  const emailInstructions = document.createElement("div");
  emailInstructions.id = "recovery-email-instructions";
  emailInstructions.hidden = true;
  $("send-recovery-email").before(emailInstructions);
  const showEmailInstructions = (request) => {
    emailInstructions.replaceChildren();
    const instruction = document.createElement("p");
    instruction.textContent = "Send this email from " + request.email + " to finish this step.";
    emailInstructions.append(instruction);
    for (const [label, value] of [["To", request.receiverAddress], ["Subject", request.subject]]) {
      const row = document.createElement("p");
      const field = document.createElement("input");
      field.readOnly = true; field.value = value; field.setAttribute("aria-label", label);
      const copy = document.createElement("button");
      copy.type = "button"; copy.textContent = "Copy " + label;
      copy.onclick = async () => {
        try { await navigator.clipboard.writeText(value); copy.textContent = "Copied " + label; }
        catch { field.focus(); field.select(); copy.textContent = "Select and copy " + label; }
      };
      row.append(label + ": ", field, copy); emailInstructions.append(row);
    }
    const to = encodeURIComponent(request.receiverAddress), subject = encodeURIComponent(request.subject);
    const providers = [
      ["Gmail", "https://mail.google.com/mail/?view=cm&to=" + to + "&su=" + subject],
      ["Outlook", "https://outlook.live.com/mail/0/deeplink/compose?to=" + to + "&subject=" + subject],
      ["iCloud", "https://www.icloud.com/mail/"],
    ];
    const domain = request.email.split("@")[1];
    const preferred = domain === "gmail.com" ? "Gmail" :
      ["outlook.com", "hotmail.com", "live.com"].includes(domain) ? "Outlook" :
      ["icloud.com", "me.com", "mac.com"].includes(domain) ? "iCloud" : "";
    providers.sort((a, b) => Number(b[0] === preferred) - Number(a[0] === preferred));
    for (const [label, href] of providers) {
      const link = document.createElement("a");
      link.textContent = "Open in " + label;
      link.setAttribute("role", "button");
      Object.assign(link.style, { display: "inline-block", padding: "10px 14px", border: "1px solid var(--line)", borderRadius: "7px", textDecoration: "none", margin: "4px 0" }); link.href = href; link.target = "_blank"; link.rel = "noopener noreferrer";
      emailInstructions.append(link, " ");
    }
    const icloudHelp = document.createElement("p");
    icloudHelp.textContent = "In iCloud, choose Compose, then paste the To and Subject above.";
    emailInstructions.append(icloudHelp);
    $("send-recovery-email").textContent = "Open email app ↗";
    $("send-recovery-email").href = request.mailto;
    $("send-recovery-email").hidden = false;
    emailInstructions.hidden = false;
    emailInstructions.scrollIntoView({ block: "nearest" });
  };
  const requestDkim = async (purpose) => {
    $("alert").hidden = true;
    dkimPoll?.abort();
    const poll = new AbortController();
    dkimPoll = poll;
    emailInstructions.hidden = true;
    $("send-recovery-email").hidden = true;
    status("Checking the recovery service…");
    if (purpose === "enroll") { requireWallet(); await beforeExport(); }
    const request = await emailGate.requestDkim($("recovery-email").value, purpose);
    if (poll.signal.aborted) return;
    showEmailInstructions(request);
    status("Waiting for your email to arrive…");
    (async () => {
      const headers = await emailGate.waitDkim(request, { signal: poll.signal });
      if (poll.signal.aborted) return;
      status("Checking your email signature in the attested gate…");
      if (request.purpose === "recover") await store("continuity.pendingEmail",
        { ...request, id: request.nonce, releaseAt: Date.now() + 48 * 60 * 60_000 });
      const result = await emailGate.confirmDkim(request, headers,
        request.purpose === "enroll" ? keys.bundle : undefined);
      if (poll.signal.aborted) return;
      emailInstructions.hidden = true;
      $("send-recovery-email").hidden = true;
      if (request.purpose === "enroll") {
        await store("continuity.email", true);
        await update();
        status("Recovery email added. Use Recover with email on another device.");
      } else {
        await store("continuity.pendingEmail", { ...request, ...result });
        showPending(result);
      }
    })().catch((e) => {
      if (e.name !== "AbortError" && dkimPoll === poll) report(e);
    }).finally(() => { if (dkimPoll === poll) dkimPoll = undefined; });
  };
  bind("enroll-email", () => requestDkim("enroll"));
  bind("request-email", () => requestDkim("recover"));
  bind("receive-device", async () => {
    await receiver?.close();
    receiver = await createDeviceLinkReceiver({ relayAddress: await discoverLinkRelay(cfg.tunnels),
      onCode, onStatus: status, confirm, onBundle: imported });
    $("link-qr").src = receiver.qrDataUrl;
    $("link-qr").hidden = false;
    $("link-qr-text").value = receiver.qr;
    $("link-qr-text").hidden = false;
    receiver.completed.then(() => location.reload()).catch((e) => { report(e); });
    status("Scan this QR with the device that has your chats, then compare the code.");
  });
  bind("send-device", async () => {
    requireWallet();
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
  serveOriginMigration({ getBundle: async () => { requireWallet(); await beforeExport(); return keys.bundle; }, confirm, onCode, onStatus: status,
    allowedOrigin: "https://private-agent.dstack.soc1024.com" }).catch((e) => { report(e); });
  window.addEventListener("pagehide", (event) => { receiver?.close(); dkimPoll?.abort(); if (!event.persisted) stopRecoveryNotice(); });
  update().catch(report);
  return { bind, status, update };
}
