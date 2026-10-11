// Isolated genuine Intel DCAP path; never inject a synthetic adapter here.
import { getCollateralAndVerify, INTEL_PCS_URL, Quote } from "@phala/dcap-qvl";
let input = "";
try {
  for await (const chunk of process.stdin) {
    if (input.length + chunk.length > 262144) throw new Error();
    input += chunk.toString("ascii");
  }
  if (!/^(?:[0-9a-f]{2})+$/.test(input)) throw new Error();
  const raw = Buffer.from(input, "hex"), parsed = Quote.parse(raw);
  // Deliberately narrow first profile: TDX quote v4 / TD10 only.
  if (parsed.header.version !== 4 || parsed.header.teeType !== 0x81) throw new Error();
  const v = await getCollateralAndVerify(raw, INTEL_PCS_URL), td = v.report.asTd10();
  if (!td || v.report.type !== "td10" || v.status !== "UpToDate") throw new Error();
  const toHex = (value) => Buffer.from(value).toString("hex");
  process.stdout.write(JSON.stringify({ quoteVersion: parsed.header.version, reportType: v.report.type, status: v.status,
    reportData: toHex(td.reportData), tdAttributes: toHex(td.tdAttributes), mrTd: toHex(td.mrTd),
    rtMr0: toHex(td.rtMr0), rtMr1: toHex(td.rtMr1), rtMr2: toHex(td.rtMr2), rtMr3: toHex(td.rtMr3) }));
} catch { process.exitCode = 1; }
