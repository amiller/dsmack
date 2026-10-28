import {
  abi,
  CHAIN,
  Contract,
  FetchRequest,
  json,
  JsonRpcProvider,
  nodeBindingSigner,
  receiptSigner,
  require,
  Wallet,
} from "./schema.mjs";

// Use Deno's TLS transport consistently for quorum reads and signed submissions.
export function providerFor(cfg) {
  const connection = new FetchRequest(cfg.rpcs[0]);
  connection.allowGzip = false;
  const client = cfg.rpcProxy
    ? Deno.createHttpClient({ proxy: { url: cfg.rpcProxy } })
    : cfg.rpcIpv4
    ? Deno.createHttpClient({ localAddress: "0.0.0.0" })
    : undefined;
  connection.getUrlFunc = async (request) => {
    const response = await fetch(request.url, {
      client,
      method: request.method,
      headers: request.headers,
      body: request.body,
      signal: AbortSignal.timeout(Math.min(request.timeout, 30000)),
    });
    return {
      statusCode: response.status,
      statusMessage: response.statusText,
      headers: Object.fromEntries(response.headers),
      body: new Uint8Array(await response.arrayBuffer()),
    };
  };
  return new JsonRpcProvider(connection, CHAIN, {
    batchMaxCount: 1,
    cacheTimeout: -1,
  });
}

// This CLI sends transactions only when explicitly run with --send by its operator.
export async function sender(cfg, keyPath, funding = true) {
  require(
    !keyPath.includes("deployer-new.key"),
    "deployer key is handled only by Andrew's script",
  );
  const st = await Deno.stat(keyPath);
  require((st.mode & 0o077) === 0, "wallet key must be mode 600");
  const provider = providerFor(cfg);
  require(
    Number((await provider.getNetwork()).chainId) === CHAIN,
    "Base Sepolia only",
  );
  let wallet;
  try {
    wallet = new Wallet((await Deno.readTextFile(keyPath)).trim(), provider);
  } catch {
    throw new Error("cannot load a valid testnet wallet key");
  }
  require(
    !funding ||
      cfg.fundingAddress &&
        wallet.address.toLowerCase() === cfg.fundingAddress.toLowerCase(),
    "single configured funding wallet required",
  );
  if (funding) {
    const { Quorum } = await import("./quorum.mjs");
    const s = await new Quorum(cfg).snapshot();
    require(
      BigInt(await s.read("eth_getBalance", [wallet.address, s.tag])) >=
        20000000000000000n,
      "funding wallet below 0.02 ETH reserve",
    );
  }
  return { provider, wallet, contract: new Contract(cfg.escrow, abi, wallet) };
}
export async function settle(cfg, contract, envelopes) {
  const seen = new Set();
  for (const e of envelopes) {
    require(
      nodeBindingSigner(cfg.escrow, e.nodeBinding).toLowerCase() ===
        cfg.grantSigner.toLowerCase(),
      "broker binding signer",
    );
    require(
      receiptSigner(cfg.escrow, e).toLowerCase() ===
        e.nodeBinding.binding.receiptSigner.toLowerCase(),
      "guest receipt key",
    );
    require(
      !seen.has(e.receipt.purchaseId),
      "one cumulative receipt per purchase per batch",
    );
    seen.add(e.receipt.purchaseId);
  }
  require(
    envelopes.every((e) =>
      json(e.nodeBinding) === json(envelopes[0].nodeBinding)
    ),
    "settlement batch must share one run binding",
  );
  const tx = await contract.settle(
    envelopes.map((e) => e.receipt),
    envelopes.map((e) => e.signature),
    envelopes[0].nodeBinding.binding,
    envelopes[0].nodeBinding.signature,
  );
  const receipt = await tx.wait();
  require(receipt.status === 1, "settlement reverted");
  return receipt.hash;
}
if (import.meta.main) {
  const [config, keyPath, command, ...args] = Deno.args;
  const send = args.pop(), file = args[0];
  require(
    send === "--send",
    "usage: submit.mjs CONFIG FUNDING_KEY settle RECEIPTS_JSON --send | refund PURCHASE_ID --send | withdraw PAYEE_KEY --send",
  );
  const cfg = JSON.parse(await Deno.readTextFile(config));
  const { Quorum } = await import("./quorum.mjs");
  await new Quorum(cfg).snapshot();
  const { contract } = await sender(cfg, keyPath, command !== "withdraw");
  if (command === "settle") {
    console.log(
      json({
        settlement: await settle(
          cfg,
          contract,
          JSON.parse(await Deno.readTextFile(file)),
        ),
      }),
    );
  } else if (command === "refund") {
    console.log(
      json({ refund: (await (await contract.refund(file)).wait()).hash }),
    );
  } else if (command === "withdraw") {
    console.log(
      json({ withdrawal: (await (await contract.withdraw()).wait()).hash }),
    );
  } else throw new Error("unknown settlement command");
}
