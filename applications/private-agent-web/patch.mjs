import { applyPatch, parsePatch } from "diff";

const require = (ok, message) => {
  if (!ok) throw new Error(message);
};
function path(value, prefix) {
  if (value === "/dev/null") return null;
  const name = value?.startsWith(prefix) ? value.slice(prefix.length) : value;
  require(
    typeof name === "string" && name.length > 0 && !name.startsWith("/") &&
      !name.includes("\\") && !name.includes("\0") &&
      !name.split("/").some((part) => part === ".." || part === ".git"),
    "The verified patch names a file outside the repository.",
  );
  return name;
}

// Apply only after node/job evidence and all decrypted output hashes pass.
// Work on a copy so a failed hunk never leaves a partially changed repository.
export function applyVerifiedPatch(files, text) {
  const updated = new Map(files), changes = [];
  for (const patch of parsePatch(text)) {
    const before = path(patch.oldFileName, "a/"),
      after = path(patch.newFileName, "b/");
    require(
      before === null || updated.has(before),
      "The verified patch does not match the repository snapshot.",
    );
    require(
      after === null || before === after || !updated.has(after),
      "The verified patch would replace another file.",
    );
    const value = applyPatch(
      before === null ? "" : updated.get(before),
      patch,
      { fuzzFactor: 0, autoConvertLineEndings: false },
    );
    require(
      value !== false,
      "The verified patch could not be applied to the repository snapshot.",
    );
    if (before !== null && before !== after) updated.delete(before);
    if (after !== null) updated.set(after, value);
    changes.push(after ?? before);
  }
  return { files: updated, changes };
}
