import { Contract, JsonRpcProvider } from "ethers";
export async function latestPageCID(config) {
  if (!config?.registry || config.rpcs?.length !== 2 || config.rpcs[0] === config.rpcs[1]) throw Error("Page version registry needs two independent RPCs.");
  const providers = config.rpcs.map(url => new JsonRpcProvider(url));
  try {
    const chains = await Promise.all(providers.map(p => p.send("eth_chainId", [])));
    if (chains.some(c => BigInt(c) !== 84532n)) throw Error("Page version registry RPC has the wrong chain.");
    const blocks = await Promise.all(providers.map(p => p.send("eth_blockNumber", [])));
    const blockTag = "0x" + BigInt(blocks.reduce((a,b) => BigInt(a)<BigInt(b)?a:b)).toString(16);
    const values = await Promise.all(providers.map(p => new Contract(config.registry, ["function latestCID() view returns (string)"], p).latestCID({blockTag})));
    if (values[0] !== values[1] || !/^bafkrei[a-z2-7]{52}$/.test(values[0])) throw Error("Page version registry returned no agreed bundle CID.");
    return values[0];
  } finally { providers.forEach(p => p.destroy()); }
}
export async function checkPageVersion({ ownCID, config, banner, latest = latestPageCID }) {
  if (!/^bafkrei[a-z2-7]{52}$/.test(ownCID)) throw Error("This page has no valid bundle CID.");
  const published = await latest(config);
  banner.hidden = ownCID === published;
  banner.textContent = banner.hidden ? "" : `This page version changed · This page: ${ownCID} · Published: ${published}`;
  return published;
}
