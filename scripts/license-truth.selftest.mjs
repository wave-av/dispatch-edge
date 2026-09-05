#!/usr/bin/env node
// license-truth.selftest — drills the detector RED on seeded violations before it is
// trusted to report on the real repo. A detector that cannot catch a PLANTED bug is
// not evidence about anything. Mirrors the shape of the org-wide
// governance/test/license-truth.selftest.mjs in claude-workstation.
//
// Exit 0 iff every seeded case produced the expected verdict; exit 1 otherwise.
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { auditRepo } from "./license-truth.mjs";

const APACHE = `                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

Licensed under the Apache License, Version 2.0 (the "License");`;
const MIT = `Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction.`;

let failures = 0;
function check(name, cond) {
  if (cond) { console.log(`  ok  ${name}`); }
  else { console.error(`  FAIL ${name}`); failures += 1; }
}

function withFixture(files, fn) {
  const dir = mkdtempSync(join(tmpdir(), "license-truth-selftest-"));
  try {
    for (const [path, content] of Object.entries(files)) {
      const full = join(dir, path);
      mkdirSync(full.slice(0, full.lastIndexOf("/")), { recursive: true });
      writeFileSync(full, content);
    }
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

console.log("license-truth.selftest — planting known-bad shapes, expecting RED\n");

// Case 1: declares MIT, ships Apache-2.0 text — the actual #451 defect this gate exists for.
withFixture({
  "sdk/js/package.json": JSON.stringify({ name: "@x/y", license: "MIT", files: ["index.js"] }),
  "sdk/js/LICENSE": APACHE,
}, (dir) => {
  const r = auditRepo(dir);
  check("declares MIT / ships Apache-2.0 -> red", r.findings.some((f) => f.rule === "declared-vs-shipped-divergence"));
});

// Case 2: declares Apache-2.0, ships MIT text (the mirror image).
withFixture({
  "sdk/py/pyproject.toml": `[project]\nname = "y"\nlicense = "Apache-2.0"\n`,
  "sdk/py/LICENSE": MIT,
}, (dir) => {
  const r = auditRepo(dir);
  check("declares Apache-2.0 / ships MIT -> red", r.findings.some((f) => f.rule === "declared-vs-shipped-divergence"));
});

// Case 3: declares a license, no LICENSE file anywhere in the package directory
// (npm/cargo never walk up to a repo root — this is the class a root-only check misses).
withFixture({
  "sdk/rs/Cargo.toml": `[package]\nname = "y"\nlicense = "Apache-2.0"\n`,
  "LICENSE": APACHE, // present at repo root only — must NOT satisfy the strict subpackage check
}, (dir) => {
  const r = auditRepo(dir);
  check("declares a license / no LICENSE in package dir (root does not count) -> red",
    r.findings.some((f) => f.rule === "license-file-missing-in-package-dir"));
});

// Case 4: gemspec declares a license, LICENSE file sits right beside it, but s.files
// never names it — RubyGems ships exactly what s.files lists, nothing more.
withFixture({
  "sdk/rb/wave.gemspec": `Gem::Specification.new do |s|\n  s.name = "y"\n  s.license = "Apache-2.0"\n  s.files = ["lib/y.rb"]\nend\n`,
  "sdk/rb/LICENSE": APACHE,
}, (dir) => {
  const r = auditRepo(dir);
  check("gemspec omits LICENSE from s.files -> red", r.findings.some((f) => f.rule === "license-not-in-gem-files"));
});

// Case 5: empty LICENSE file.
withFixture({
  "sdk/go/package.json": JSON.stringify({ name: "@x/z", license: "MIT" }),
  "sdk/go/LICENSE": "",
}, (dir) => {
  const r = auditRepo(dir);
  check("empty LICENSE file -> red", r.findings.some((f) => f.rule === "license-file-empty"));
});

console.log("\nlicense-truth.selftest — consistent input, expecting GREEN\n");

// Consistent case must NOT go red — a detector that always fires is as useless as one that never does.
withFixture({
  "sdk/js/package.json": JSON.stringify({ name: "@x/y", license: "Apache-2.0" }),
  "sdk/js/LICENSE": APACHE,
}, (dir) => {
  const r = auditRepo(dir);
  check("declares Apache-2.0 / ships Apache-2.0 -> green", r.findings.length === 0);
});

console.log("\nlicense-truth.selftest — the third state: absent input is a FAILURE, not a pass\n");

withFixture({}, (dir) => {
  const r = auditRepo(dir);
  check("0 manifests -> caller must treat as CANNOT-MEASURE (empty manifestPaths)", r.manifestPaths.length === 0);
});
withFixture({ "sdk/go/go.mod": "module x\n\ngo 1.25\n" }, (dir) => {
  const r = auditRepo(dir);
  check("manifests present but none declares a license -> declaredCount 0", r.manifestPaths.length === 0 && r.declaredCount === 0);
  // go.mod is intentionally not a MANIFEST_RE match (no license field to audit),
  // so this fixture also proves manifestPaths stays empty rather than false-counting it.
});

if (failures) {
  console.error(`\n${failures} selftest case(s) FAILED — the detector cannot be trusted; not running it against the real repo.`);
  process.exit(1);
}
console.log("\nAll selftest cases passed — the detector catches every seeded shape.");
process.exit(0);
