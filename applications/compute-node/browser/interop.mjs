// Python drives this process; private output keys remain inside WebCrypto.
import readline from "node:readline";
import { createClient, hex, sealJob, unhex } from "./sandbox.mjs";
import { open } from "../../../dstack-compat/secret-release/policy.mjs";
const lines = readline.createInterface({ input: process.stdin });
const it = lines[Symbol.asyncIterator]();
const read = async () => JSON.parse((await it.next()).value),
  send = (value) => process.stdout.write(JSON.stringify(value) + "\n");
const init = await read(), client = await createClient();
send({ peer: client.peer });
const grant = await read(),
  job = await sealJob({
    registration: { relay_peer: init.peer, secret_key: init.secret },
    policy: { brokerKey: init.broker },
  }, {
    grant,
    jobId: init.jobId,
    credential: { test: "cross-language" },
    repoTar: new TextEncoder().encode("toy archive bytes"),
    prompt: "edit π <tag> & UTF-8",
    client,
  });
send({ sealed: job.sealed, output_pub: hex(job.outputKey.pub) });
const outputs = await read(), plain = {};
for (const [name, box] of Object.entries(outputs)) {
  plain[name] = new TextDecoder().decode(
    await open(job.outputKey, box, init.jobId + "/" + name),
  );
}
send(plain);
lines.close();
