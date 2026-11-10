import {
  abi,
  CHAIN,
  Contract,
  FetchRequest,
  json,
  JsonRpcProvider,
  Claim,
  claimDomain,
  verifyTypedData,
  require,
  Wallet,
} from "./schema.mjs";

// Use Deno's TLS transport consistently for chain reads and signed submissions.
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
    const { ChainReader } = await import("./chain-reader.mjs");
    const s = await new ChainReader(cfg).snapshot();
    require(
      BigInt(await s.read("eth_getBalance", [wallet.address, s.tag])) >=
        20000000000000000n,
      "funding wallet below 0.02 ETH reserve",
    );
  }
  return { provider, wallet, contract: new Contract(cfg.escrow, abi, wallet) };
}
if (import.meta.main) {
  const [config, keyPath, command, value, flag] = Deno.args;
  require(flag === "--send" || value === "--send",
    "usage: submit.mjs CONFIG WALLET_KEY deposit USDC_BASE_UNITS --send | claim CLAIM_JSON --send | request-exit --send | withdraw --send");
  const cfg = JSON.parse(await Deno.readTextFile(config));
  const { ChainReader } = await import("./chain-reader.mjs");
  await new ChainReader(cfg).snapshot();
  const { contract, wallet } = await sender(cfg, keyPath, false);
  let tx;
  if (command === "deposit") {
    require(/^[1-9][0-9]*$/.test(value), "positive USDC base units required");
    const token = new Contract(await contract.token(), ["function approve(address,uint256) returns(bool)"], wallet);
    await (await token.approve(cfg.escrow, value)).wait();
    tx = await contract.deposit(value);
  } else if (command === "claim") {
    const envelope = JSON.parse(await Deno.readTextFile(value));
    require(verifyTypedData(claimDomain(cfg.escrow, envelope.user), { Claim }, envelope.claim, envelope.signature)
      .toLowerCase() === cfg.grantSigner.toLowerCase(), "broker claim signature");
    tx = await contract.claim(envelope.user, envelope.claim, envelope.signature);
  } else if (command === "request-exit") tx = await contract.requestExit();
  else if (command === "withdraw") tx = await contract.withdraw();
  else throw new Error("unknown prepaid command");
  console.log(json({ command, transaction: (await tx.wait()).hash }));
}
