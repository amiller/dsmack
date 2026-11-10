// NEAR AI Cloud deployment policy, mirroring 13rac1/teep's nearcloud checks:
// MRCONFIGID binds app_compose, every digest-pinned image is a known
// repository with Sigstore provenance, and the TD runs a known OS.
// Policy data: https://github.com/13rac1/teep at TEEP_COMMIT,
// internal/provider/{neardirect,nearcloud}/policy.go and
// internal/attestation/dstack_defaults.go. LOCAL marks values teep lacks.
export const TEEP_COMMIT = "789918ea606826650447a7f1930b917521d3d135";
const GITHUB = "https://token.actions.githubusercontent.com";
const gh = (repo, ...workflows) => ({
  provenance: "fulcio",
  issuer: GITHUB,
  identities: workflows.map((w) => `https://github.com/${repo}/.github/workflows/${w}`),
  sourceRepos: [repo, "https://github.com/" + repo],
});
const composeManager = gh("nearai/compose-manager", "build.yml@refs/heads/master", "promote.yml@refs/heads/master");
export const IMAGES = {
  "datadog/agent": { model: true, gateway: true, provenance: "key", key: "25bcab4ec8eede1e3091a14692126798c23986832ae6e5948d6f7eb0a928ab0b" },
  "certbot/dns-cloudflare": { model: true, provenance: "compose" },
  "otel/opentelemetry-collector-contrib": { model: true, gateway: true, provenance: "key", key: "a8bd282038915eaf2ca9ac7d4cc2605ce6e7ae8aed5b19b06370e285f8a9d72e" },
  "nearaidev/compose-manager": { model: true, ...composeManager },
  // LOCAL: teep requires Fulcio provenance, but Rekor and GitHub have no
  // entry for this digest (checked 2026-11-04), so only this digest is pinned.
  "nearaidev/compose-manager-launcher": { model: true, provenance: "digest", digests: ["079a14b41deb11e0e27f9b69648e8b3d89bd6fb9ccf6071643b8f447fa415085"] },
  "nearaidev/dstack-vpc-client": { gateway: true, ...gh("nearai/dstack-vpc-client", "build.yml@refs/heads/main") },
  "nearaidev/dstack-vpc": { gateway: true, ...gh("nearai/dstack-vpc", "build.yml@refs/heads/main") },
  alpine: {
    gateway: true, provenance: "fulcio", issuer: GITHUB,
    identities: [
      "https://github.com/docker/github-builder-experimental/.github/workflows/bake.yml@refs/heads/build-distributed",
      "https://github.com/crazy-max/docker-github-builder/.github/workflows/bake.yml@refs/heads/main",
    ],
    sourceRepos: [
      "docker/github-builder-experimental", "https://github.com/docker/github-builder-experimental",
      "crazy-max/docker-github-builder", "https://github.com/crazy-max/docker-github-builder",
    ],
  },
  "nearaidev/cloud-api": { gateway: true, ...gh("nearai/cloud-api", "build.yml@refs/heads/main") },
  "nearaidev/cvm-ingress": { gateway: true, ...gh("nearai/cvm-ingress", "build-push.yml@refs/heads/main") },
};
const MRSEAM = [
  "49b66faa451d19ebbdbe89371b8daf2b65aa3984ec90110343e9e2eec116af08850fa20e3b1aa9a874d77a65380ee7e6",
  "7bf063280e94fb051f5dd7b1fc59ce9aac42bb961df8d44b709c9b0ff87a7b4df648657ba6d1189589feab1d5a3c9a9d",
  "476a2997c62bccc78370913d0a80b956e3721b24272bc66c4d6307ced4be2865c40e26afac75f12df3425b03eb59ea7c",
  "685f891ea5c20e8fa27b151bf34bf3b50fbaf7143cc53662727cbdb167c0ad8385f1f6f3571539a91e104a1c96d75e04",
  "d0d80c085166ba78ccc69af268e5753cf0f3394523cb4ff7c50b08d9265c82489c099c377be6a400e4d2b57da924012c",
  "489e585f1c54bc5a02066c8c6ec21619ff0334ec6f21e07e2a35202c59183789c8057e7d97dd591bb08314b185819e72",
  "2d2de102461684f14c8d0984a09d895e3e9e15944ce020a03b977e1f114d5e1ed32ef666a47fd19a5851b3800eda3afa",
];
const MRTD = [
  "b24d3b24e9e3c16012376b52362ca09856c4adecb709d5fac33addf1c47e193da075b125b6c364115771390a5461e217",
  "f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077",
  "df4d77c857de652bd0fafa343a2026b51071ee03773d076d283abf1a7d36ff91ffa279ee4a617ac664f7e2a2c8d5891b",
];
// LOCAL: NEAR's current OS (gateway os_image_hash 8db40cb2..., model
// 91fd5d69...), observed in live quotes 2026-11-04; teep's lists predate it.
const OBSERVED_RTMR1 = "4ae609807c765916a31d724786ed74bcb97e168a9d937b04936aeef2015c907eba5ac352c6bcd749c246fd62ffb659ec";
export const OS = {
  model: {
    mrtd: MRTD,
    rtmr1: [
      "c0445b704e4c48139496ae337423ddb1dcee3a673fd5fb60a53d562f127d235f11de471a7b4ee12c9027c829786757dc",
      "ff61e68fa04516b1813d2d478397a97a58f9ccc402b6d96fb73f5e5104a4acf155913caec99a0c19afc16ae0f3a77726",
      OBSERVED_RTMR1,
    ],
    rtmr2: [
      "564622c7ddc55a53272cc9f0956d29b3f7e0dd18ede432720b71fd89e5b5d76cb0b99be7b7ff2a6a92b89b6b01643135",
      "4d662c04766145dfe084fd014969b19c387afe9bb1d4f972c6968d28a7a8b4937c414603a2cf446105eddce67a86f9ce",
      "bd67ab7554dc27ab03a077bc1447a1a67d0624ff547c4c809a8626f12d6a89712f8ec60e781e99b98208574065d21a71",
    ],
  },
  gateway: {
    mrtd: [...MRTD, "7fe60787222bd394cb516abca2435f22f035ab2cc9c0a4b4b3b148e46297f3d931a237b72f359052c6e657d8c1409173"],
    rtmr1: ["a7b523278d4f914ee8df0ec80cd1c3d498cbf1152b0c5eaf65bad9425072874a3fcf891e8b01713d3d9937e3e0d26c15", OBSERVED_RTMR1],
    rtmr2: [
      "24847f5c5a2360d030bc4f7b8577ce32e87c4d051452c937e91220cab69542daef83433947c492b9c201182fc9769bbe",
      "764489f277a8540189761e72b4238ba36d4d647e11bd958d8ab5522af2a4867b0ff63e06b0c4967f1857236244040a5d",
    ],
  },
};
const REKOR = "https://rekor.sigstore.dev";
// https://rekor.sigstore.dev/api/v1/log/publicKey (also pinned by teep).
const REKOR_KEY = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==";

const need = (ok, message) => {
  if (!ok) throw new Error("NEAR policy: " + message);
};
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const unhex = (s) => Uint8Array.from(s.match(/../g), (b) => parseInt(b, 16));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const sha256 = async (b) => new Uint8Array(await crypto.subtle.digest("SHA-256", b));
const concat = (...a) => {
  const out = new Uint8Array(a.reduce((n, x) => n + x.length, 0));
  a.reduce((o, x) => (out.set(x, o), o + x.length), 0);
  return out;
};

// TDX quote v4 TD report fields, after the 48-byte header.
export function tdFields(quoteHex) {
  need(/^(?:[0-9a-f]{2})+$/i.test(quoteHex), "quote encoding");
  const q = unhex(quoteHex);
  need(q[0] === 4 && q[1] === 0 && q.length >= 48 + 584, "TDX quote v4 required");
  const f = (offset) => hex(q.subarray(48 + offset, 48 + offset + 48));
  return { mrseam: f(16), mrtd: f(136), mrconfigid: f(184), rtmr1: f(376), rtmr2: f(424) };
}
export function checkOs(tier, quoteHex) {
  const td = tdFields(quoteHex), os = OS[tier];
  need(MRSEAM.includes(td.mrseam), "unknown TDX module " + td.mrseam.slice(0, 16));
  for (const k of ["mrtd", "rtmr1", "rtmr2"]) need(os[k].includes(td[k]), `unknown ${tier} ${k} ${td[k].slice(0, 16)}`);
}
export async function checkComposeBinding(appCompose, quoteHex) {
  const expected = "01" + hex(await sha256(new TextEncoder().encode(appCompose)));
  need(tdFields(quoteHex).mrconfigid.startsWith(expected), "MRCONFIGID does not bind app_compose");
}

// teep normalizeImageRepository: keep ${VAR:-default}'s default, drop tag.
function repository(ref) {
  ref = ref.trim().toLowerCase();
  const d = ref.indexOf(":-");
  if (d > 0 && !ref.slice(0, d).includes("/")) ref = ref.slice(d + 2);
  return ref.lastIndexOf(":") > ref.lastIndexOf("/") ? ref.slice(0, ref.lastIndexOf(":")) : ref;
}
export function composeImages(appCompose) {
  const compose = JSON.parse(appCompose).docker_compose_file;
  need(typeof compose === "string" && compose.length > 0, "docker_compose_file missing");
  for (const line of compose.split("\n")) {
    if (/^\s*image\s*:/.test(line)) need(/@sha256:[0-9a-f]{64}/.test(line), "image without digest: " + line.trim());
  }
  const images = new Map();
  for (const [, ref, digest] of compose.matchAll(/([A-Za-z0-9._/:-]+)@sha256:([0-9a-f]{64})/g)) {
    images.set(digest, repository(ref));
  }
  need(images.size > 0, "no digest-pinned images");
  return images;
}

// Minimal DER reader for Fulcio certificates.
function der(b, at = 0) {
  let len = b[at + 1], start = at + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[start + i];
    start += n;
  }
  return { tag: b[at], start, end: start + len, all: b.subarray(at, start + len) };
}
function children(b, node) {
  const out = [];
  for (let at = node.start; at < node.end;) {
    const c = der(b, at);
    out.push(c);
    at = c.end;
  }
  return out;
}
const OID_PREFIX = "060a2b0601040183bf3001"; // 1.3.6.1.4.1.57264.1
const text = (b) => new TextDecoder().decode(b);
function certificate(pem) {
  const b = unb64(pem.replace(/-----[^-]+-----|\s/g, ""));
  const tbs = children(b, children(b, der(b))[0]);
  const fields = tbs[0].tag === 0xa0 ? tbs.slice(1) : tbs;
  const spki = fields[5].all;
  const ext = {};
  const extensions = tbs.find((n) => n.tag === 0xa3);
  for (const e of extensions ? children(b, children(b, extensions)[0]) : []) {
    const parts = children(b, e);
    const oid = hex(parts[0].all), value = parts[parts.length - 1];
    const raw = b.subarray(value.start, value.end);
    if (oid === "0603551d11") {
      for (const name of children(raw, der(raw))) {
        if (name.tag === 0x86) ext.san = text(raw.subarray(name.start, name.end));
      }
    } else if (oid.startsWith(OID_PREFIX)) {
      const arc = parseInt(oid.slice(OID_PREFIX.length), 16);
      // Arcs 1-6 are raw strings; later arcs are DER UTF8String.
      ext[arc] = arc >= 8 ? text(raw.subarray(der(raw).start, der(raw).end)) : text(raw);
    }
  }
  return { spki, san: ext.san, issuer: ext[1] ?? ext[8], sourceRepo: ext[5], sourceRepoUrl: ext[12] };
}

async function verifySet(entry) {
  const key = await crypto.subtle.importKey("spki", unb64(REKOR_KEY), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  const payload = JSON.stringify({ body: entry.body, integratedTime: entry.integratedTime, logID: entry.logID, logIndex: entry.logIndex });
  const sig = unb64(entry.verification.signedEntryTimestamp), seq = der(sig), [r, s] = children(sig, seq);
  const int = (n) => sig.subarray(n.start, n.end).slice(-32);
  const raw = new Uint8Array(64);
  raw.set(int(r), 32 - int(r).length);
  raw.set(int(s), 64 - int(s).length);
  need(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, raw, new TextEncoder().encode(payload)), "Rekor SET signature");
}
// RFC 9162 section 2.1.3.2 inclusion proof.
async function verifyInclusion(entry) {
  const p = entry.verification.inclusionProof;
  need(p && p.logIndex >= 0 && p.logIndex < p.treeSize && p.hashes.length <= 64, "Rekor inclusion proof");
  let fn = p.logIndex, sn = p.treeSize - 1;
  let r = await sha256(concat([0], unb64(entry.body)));
  for (const h of p.hashes.map(unhex)) {
    need(sn > 0, "Rekor inclusion proof length");
    if (fn % 2 === 1 || fn === sn) {
      r = await sha256(concat([1], h, r));
      if (fn % 2 === 0) while (fn % 2 === 0 && fn !== 0) [fn, sn] = [Math.floor(fn / 2), Math.floor(sn / 2)];
    } else r = await sha256(concat([1], r, h));
    [fn, sn] = [Math.floor(fn / 2), Math.floor(sn / 2)];
  }
  need(sn === 0 && hex(r) === p.rootHash, "Rekor inclusion proof root");
}
async function signer(entry) {
  const body = JSON.parse(text(unb64(entry.body)));
  const verifier = body.spec?.signatures?.[0]?.verifier;
  if (!verifier) return undefined;
  const pem = text(unb64(verifier));
  if (pem.includes("BEGIN PUBLIC KEY")) return { key: hex(await sha256(unb64(pem.replace(/-----[^-]+-----|\s/g, "")))) };
  if (!pem.includes("BEGIN CERTIFICATE")) return undefined;
  const c = certificate(pem);
  return { ...c, key: hex(await sha256(c.spki)) };
}
function accepts(policy, s) {
  if (policy.provenance === "key") return s.key === policy.key;
  return s.issuer === policy.issuer && policy.identities.includes(s.san) &&
    (policy.sourceRepos.includes(s.sourceRepo) || policy.sourceRepos.includes(s.sourceRepoUrl));
}
async function rekor(fetcher, path, body) {
  const r = await fetcher(REKOR + path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  need(r.ok, `Rekor ${path} HTTP ${r.status}`);
  return await r.json();
}
const proven = new Map();
async function checkProvenance(digest, repo, policy, fetcher) {
  const id = digest + " " + repo;
  if (proven.has(id)) return;
  const uuids = await rekor(fetcher, "/api/v1/index/retrieve", { hash: "sha256:" + digest });
  need(uuids.length > 0, `no Rekor entry for ${repo}@sha256:${digest}`);
  for (let i = 0; i < uuids.length; i += 10) {
    for (const item of await rekor(fetcher, "/api/v1/log/entries/retrieve", { entryUUIDs: uuids.slice(i, i + 10) })) {
      const entry = Object.values(item)[0], s = await signer(entry);
      if (s && accepts(policy, s)) {
        await verifySet(entry);
        await verifyInclusion(entry);
        proven.set(id, true);
        return;
      }
    }
  }
  need(false, `no Rekor entry for ${repo}@sha256:${digest} matches its signer policy`);
}
export async function checkImages(tier, appCompose, fetcher = fetch) {
  await Promise.all([...composeImages(appCompose)].map(([digest, repo]) => {
    const policy = IMAGES[repo];
    need(policy?.[tier], `${repo} is not an approved ${tier} image`);
    if (policy.provenance === "compose") return;
    if (policy.provenance === "digest") return need(policy.digests.includes(digest), `${repo}@sha256:${digest} is not pinned`);
    return checkProvenance(digest, repo, policy, fetcher);
  }));
}

// SDK verifiers for one attestation. Every quote the SDK authenticates with
// tdxQuote (the TD's and its compose manager's) must run a known OS; the
// deployment must be the app_compose bound to this attestation's quote.
export function nearVerifiers(tier, intelQuote, tdxQuote, fetcher = fetch) {
  return {
    tdxQuote: async (quote) => {
      const verified = await tdxQuote(quote);
      checkOs(tier, quote);
      return verified;
    },
    deployment: async (deployment) => {
      await checkComposeBinding(deployment.appCompose, intelQuote);
      await checkImages(tier, deployment.appCompose, fetcher);
    },
  };
}
