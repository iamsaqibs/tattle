// Offline validator for src/data/hosts.json.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const data = JSON.parse(readFileSync(join(root, "src/data/hosts.json"), "utf8"));
const errs = [];
const seen = new Set();
if (data.version !== 1) errs.push("version must be 1");
if (!/^\d{4}-\d{2}-\d{2}$/.test(data.updated ?? "")) errs.push("updated must be YYYY-MM-DD");
for (const [i, r] of (data.rules ?? []).entries()) {
  const w = `rule #${i} (${r.pattern})`;
  if (typeof r.pattern !== "string" || !/^[a-z0-9*.-]+$/.test(r.pattern)) errs.push(`${w}: bad pattern (lowercase only)`);
  else if (seen.has(r.pattern)) errs.push(`${w}: duplicate`);
  else seen.add(r.pattern);
  if (r.class !== "good" && r.class !== "telemetry") errs.push(`${w}: invalid class`);
  if (!r.vendor) errs.push(`${w}: missing vendor`);
  if (!r.category) errs.push(`${w}: missing category`);
  if (!/^https:\/\/[^\s]+$/.test(r.source ?? "")) errs.push(`${w}: missing/invalid https source`);
}
if (errs.length) { console.error(errs.join("\n")); process.exit(1); }
console.log(`hosts.json OK (${data.rules.length} rules)`);
