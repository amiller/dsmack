// Run on the credential's existing laptop. Only ciphertext is written.
import { encryptEnvelope } from "./provider-env.mjs";

if (import.meta.main) {
  try {
    const [publicInfoPath, expectedSigner, keyPath, output] = Deno.args;
    if (!output || Deno.args.length !== 4) {
      throw new Error("arguments");
    }
    const publicInfo = JSON.parse(await Deno.readTextFile(publicInfoPath));
    const raw = (await Deno.readTextFile(keyPath)).trim();
    // Accept the existing raw inference key or its named encrypted-env payload.
    const payload = raw.startsWith("{")
      ? JSON.parse(raw)
      : { NEAR_API_KEY: raw };
    const envelope = await encryptEnvelope(publicInfo, payload, expectedSigner);
    await Deno.writeTextFile(output, JSON.stringify(envelope) + "\n", {
      mode: 0o600,
      createNew: true,
    });
    console.log("Encrypted provider environment written");
  } catch {
    console.error("Provider environment encryption failed");
    Deno.exit(1);
  }
}
