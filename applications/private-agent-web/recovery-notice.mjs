// Every device with the DK can discover and cancel email recovery directly at
// the gate, including QR/passkey-linked devices that do not know the email.
export function watchRecovery({ gate, getBundle }) {
  const notice = document.getElementById('email-recovery-notice');
  const text = document.getElementById('email-recovery-notice-text');
  const cancel = document.getElementById('cancel-email-recovery');
  let pending, busy = false, stopped = false;
  const report = error => {
    notice.hidden = false;
    text.textContent = 'Couldn’t check email recovery: ' + error.message;
  };
  const check = async () => {
    if (busy || stopped || document.hidden || !getBundle()) return;
    busy = true;
    try {
      ({ pending } = await gate.status(getBundle().dk));
      if (stopped) return;
      notice.hidden = !pending;
      cancel.hidden = !pending;
      if (pending) text.textContent = 'Someone requested your wallet and chats by email. Keys can be released after ' +
        new Date(pending.releaseAt).toLocaleString() + '. Cancel now if this wasn’t you.';
    } catch (e) { report(e); }
    finally { busy = false; }
  };
  cancel.onclick = async () => {
    if (busy || !pending) return;
    busy = true; cancel.disabled = true;
    try {
      await gate.cancel(getBundle().dk, pending.id);
      pending = null; cancel.hidden = true;
      text.textContent = 'Email recovery cancelled. Your keys were not released to that request.';
    } catch (e) { report(e); }
    finally { busy = false; cancel.disabled = false; }
  };
  const timer = setInterval(check, 60_000);
  document.addEventListener('visibilitychange', check);
  window.addEventListener('pageshow', check);
  check();
  return () => {
    stopped = true; clearInterval(timer);
    document.removeEventListener('visibilitychange', check);
    window.removeEventListener('pageshow', check);
  };
}
