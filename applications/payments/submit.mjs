import {
  abi,
  CHAIN,
  Contract,
  json,
  JsonRpcProvider,
  receiptSigner,
  require,
  Wallet,
} from "./schema.mjs";

// This CLI sends transactions only when explicitly run with --send by its operator.
export async function sender(cfg, keyPath, funding = true) {
  require(
    !keyPath.includes("deployer-new.key"),
    "deployer key is handled only by Andrew's script",
  );
  const st = await Deno.stat(keyPath);
  require((st.mode & 0o077) === 0, "wallet key must be mode 600");
  const provider = new JsonRpcProvider(cfg.rpcs[0], CHAIN, {
    batchMaxCount: 1,
    cacheTimeout: -1,
  });
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
  return { provider, wallet, contract: new Contract(cfg.escrow, abi, wallet) };
}
export async function settle(cfg, contract, envelopes) {
  const seen = new Set();
  for (const e of envelopes) {
    receiptSigner(cfg.escrow, e);
    require(
      !seen.has(e.receipt.purchaseId),
      "one cumulative receipt per purchase per batch",
    );
    seen.add(e.receipt.purchaseId);
  }
  const tx = await contract.settle(
    envelopes.map((e) => e.receipt),
    envelopes.map((e) => e.signature),
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
