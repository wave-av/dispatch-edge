#!/usr/bin/env node
// license-truth — the repo-local LEGAL-001 gate for dispatch-edge.
//
// WHAT IT CATCHES: any of the five SDK subdirectories (go, js, python, ruby, rust)
// declaring a license in its own manifest that the LICENSE TEXT beside it does not
// back up — either because the text says something else (the #451 defect: every
// manifest here said MIT while LICENSE had been Apache-2.0 since e3b3fb8) or
// because there is no LICENSE text in that subpackage's own directory at all (npm
// and cargo pack from the package directory only, and never walk up to the repo
// root — a green root-level check would miss this class entirely).
//
// FAILS CLOSED. Absent input is a FAILURE, never a pass: zero manifests found, or
// zero of them declaring a license, means this gate could not measure anything —
// that is reported as a failure (exit 1), not a skip and not a green.
//
// Usage: node scripts/license-truth.mjs [--json]
// Exit: 0 consistent · 1 divergence found OR could not measure anything.
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  identifyLicenseText, declarationMatches, parseManifest,
  resolveShippedLicense, MANIFEST_RE, LICENSE_FILE_RE, VENDOR_RE,
} from "./lib/license-truth.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function walk(dir, out) {
  let entries;
  try { entries = readdirSync(dir); } catch { return; }
  for (const name of entries) {
    const p = join(dir, name);
    const rel = relative(ROOT, p);
    if (rel.startsWith(".git")) continue;
    if (VENDOR_RE.test(rel)) continue;
    let st;
    try { st = statSync(p); } catch { continue; }
    if (st.isDirectory()) walk(p, out);
    else out.push(rel);
  }
}

export function auditRepo(root = ROOT) {
  const files = [];
  walk(root, files);
  const licensePaths = files.filter((f) => LICENSE_FILE_RE.test(f));
  const manifestPaths = files.filter((f) => MANIFEST_RE.test(f));

  const licenseId = new Map();
  for (const p of licensePaths) {
    try { licenseId.set(p, identifyLicenseText(readFileSync(join(root, p), "utf8"))); }
    catch { licenseId.set(p, "UNREADABLE"); }
  }

  const findings = [];
  const units = [];
  let declaredCount = 0;

  for (const mp of manifestPaths) {
    let raw;
    try { raw = readFileSync(join(root, mp), "utf8"); } catch { continue; }
    const m = parseManifest(mp, raw);
    if (!m || m.private || (!m.declared && !m.licenseByFile)) continue;
    declaredCount += 1;

    const shippedPath = resolveShippedLicense(mp, licensePaths, { strict: true });
    const shipped = shippedPath ? licenseId.get(shippedPath) : "NO-LICENSE-FILE";
    const unit = { manifest: mp, pkg: m.name, ecosystem: m.ecosystem, declared: m.declared, shipped, shippedFrom: shippedPath };
    units.push(unit);
    const dir = mp.replace(/[^/]+$/, "") || "./";

    if (!shippedPath) {
      findings.push({ ...unit, rule: "license-file-missing-in-package-dir",
        detail: `${m.name ?? mp} declares ${m.declared} but ${dir} contains no LICENSE — the published artifact would carry no license text of its own.` });
      continue;
    }

    // Ecosystems that do NOT auto-include a colocated LICENSE in the published
    // artifact must say so explicitly. npm always includes a colocated LICENSE
    // regardless of `files` (documented npm-packlist behavior), and cargo's
    // default packlist is every git-tracked file in the package directory unless
    // `exclude` says otherwise — so both are covered by the colocation check
    // above, PLUS an explicit veto check here for the ways each can still opt out.
    if (m.ecosystem === "rubygems") {
      const licenseBase = shippedPath.split("/").pop();
      if (m.files === null || !new RegExp(`(^|[\\s'",])${licenseBase}([\\s'",]|$)`).test(m.files)) {
        findings.push({ ...unit, rule: "license-not-in-gem-files",
          detail: `${m.name ?? mp}: ${shippedPath} exists but s.files does not list it — RubyGems ships exactly the files named in s.files, nothing more.` });
      }
    }
    if (m.ecosystem === "cargo" && m.excludesLicense) {
      findings.push({ ...unit, rule: "license-excluded-from-crate",
        detail: `${m.name ?? mp}: Cargo.toml's [package].exclude removes the LICENSE file from the published crate.` });
    }
    if (m.ecosystem === "cargo" && m.include && !new RegExp(`LICEN[CS]E`, "i").test(m.include)) {
      findings.push({ ...unit, rule: "license-absent-from-crate-include",
        detail: `${m.name ?? mp}: Cargo.toml sets [package].include and it does not name the LICENSE file, so cargo would omit it.` });
    }

    const verdict = declarationMatches(m.declared, shipped);
    if (!verdict.ok) {
      findings.push({ ...unit, rule: verdict.reason,
        detail: `${m.name ?? mp} declares ${m.declared ?? "(nothing)"} but ships ${shipped} — ${shippedPath}.` });
    }
  }

  return { files, licensePaths, manifestPaths, declaredCount, units, findings };
}

function main() {
  const json = process.argv.includes("--json");
  const result = auditRepo(ROOT);

  if (result.manifestPaths.length === 0) {
    console.error("license-truth: 0 publishable manifests found in this repo — CANNOT MEASURE. An empty denominator is not a pass.");
    return 1;
  }
  if (result.declaredCount === 0) {
    console.error(`license-truth: ${result.manifestPaths.length} manifest(s) found but none declares a license — CANNOT MEASURE. An unmeasured license state is not a passing one.`);
    return 1;
  }

  if (json) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return result.findings.length ? 1 : 0;
  }

  console.log(`license-truth: ${result.manifestPaths.length} manifest(s) checked, ${result.declaredCount} declaring a license, ${result.licensePaths.length} LICENSE file(s) found`);
  for (const u of result.units) console.log(`  ${u.manifest}: declares ${u.declared ?? "(none)"} — ships ${u.shipped}${u.shippedFrom ? ` (${u.shippedFrom})` : ""}`);

  if (result.findings.length === 0) {
    console.log("\nOK — every declared license matches the license text shipped beside it, in its own package directory.");
    return 0;
  }

  console.error(`\n${result.findings.length} unit(s) declare a license they do not (correctly) ship:`);
  for (const f of result.findings) console.error(`  [${f.rule}] ${f.manifest}\n      ${f.detail}`);
  return 1;
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  process.exit(main());
}
