import { Wallet } from "../payments/schema.mjs";
import { decryptEnvelope, encryptEnvelope, info } from "./provider-env.mjs";

const assert = (ok) => {
  if (!ok) throw new Error("assertion failed");
};
async function refused(fn, message) {
  let error;
  try {
    await fn();
  } catch (e) {
    error = e;
  }
  assert(error?.message === message);
}

Deno.test("provider env round-trip stores ciphertext and accepts only supported credentials", async () => {
  const recipient = Wallet.createRandom(), payment = Wallet.createRandom();
  const publicInfo = await info(recipient, payment);
  const secrets = {
    NEAR_API_KEY: "synthetic-inference-fixture",
    NEAR_MANAGEMENT_TOKEN: "synthetic-management-fixture",
    NEAR_REPORTING_TOKEN: "synthetic-reporting-fixture",
  };
  const envelope = await encryptEnvelope(publicInfo, secrets, payment.address);
  assert(
    Object.keys(envelope).sort().join() ===
      "ciphertext,ephemeralPublicKey,iv,v",
  );
  assert(!JSON.stringify(envelope).includes("synthetic-"));
  assert(
    JSON.stringify(await decryptEnvelope(envelope, recipient)) ===
      JSON.stringify(secrets),
  );
  await refused(
    () =>
      encryptEnvelope(publicInfo, { UNKNOWN_KEY: "fixture" }, payment.address),
    "provider environment encryption refused",
  );
});

Deno.test("provider env refuses an untrusted payment signer or swapped encryption recipient", async () => {
  const recipient = Wallet.createRandom(),
    payment = Wallet.createRandom(),
    other = Wallet.createRandom();
  const publicInfo = await info(recipient, payment);
  await refused(
    () =>
      encryptEnvelope(publicInfo, { NEAR_API_KEY: "fixture" }, other.address),
    "provider environment encryption refused",
  );
  await refused(
    () =>
      encryptEnvelope(
        { ...publicInfo, publicKey: other.signingKey.publicKey },
        { NEAR_API_KEY: "fixture" },
        payment.address,
      ),
    "provider environment encryption refused",
  );
});

Deno.test("provider env rejects wrong recipient, changed ciphertext, and malformed envelope", async () => {
  const recipient = Wallet.createRandom(), payment = Wallet.createRandom();
  const envelope = await encryptEnvelope(await info(recipient, payment), {
    NEAR_API_KEY: "fixture",
  }, payment.address);
  await refused(
    () => decryptEnvelope(envelope, Wallet.createRandom()),
    "provider environment decryption refused",
  );
  const first = envelope.ciphertext.slice(0, 2) === "00" ? "01" : "00";
  await refused(
    () =>
      decryptEnvelope({
        ...envelope,
        ciphertext: first + envelope.ciphertext.slice(2),
      }, recipient),
    "provider environment decryption refused",
  );
  await refused(
    () => decryptEnvelope({ ...envelope, v: 2 }, recipient),
    "provider environment decryption refused",
  );
});
