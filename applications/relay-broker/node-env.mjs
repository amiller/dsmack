// Container isolation runs Deno with --deny-env. Bundled npm code (debug, ws)
// reads process.env at import and would throw, so it sees an empty environment.
import process from "node:process";
if (Deno.permissions.querySync({ name: "env" }).state !== "granted") {
  Object.defineProperty(process, "env", { value: {} });
}
