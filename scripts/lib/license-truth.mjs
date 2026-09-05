// license-truth — pure license-identity logic for LEGAL-001 (dispatch-edge#39 gate).
//
// Vendored from wave-av/claude-workstation governance/lib/license-truth.mjs, which is
// designed to be shared: "the fleet driver, a repo-local gate and the drill can all
// share one definition of 'what license is this really'." No IO, no network — every
// function here takes text it has already been given and returns a verdict.
//
// The one idea worth holding: you cannot catch a declared-vs-shipped license
// contradiction by comparing declarations to each other. Both sides can agree and
// still both be wrong about the file that actually travels. The only way is to READ
// THE LICENSE TEXT AND NAME IT.
//
// dispatch-edge is a monorepo with five SDK subdirectories (go, js, python, ruby,
// rust) each publishing to its own registry. npm and cargo pack from the PACKAGE
// directory and never walk up to a repo root — that is exactly the defect class
// this gate exists to catch (a subpackage declaring a license while shipping none
// of its own, silently relying on a root LICENSE that never travels with the
// published artifact). `resolveShippedLicense` is always called here with
// `strict: true` for that reason: every subpackage must carry its own copy.

// Ordered most-specific-first. Each pattern targets a phrase that appears only
// inside that license's body, never a mere mention of its name.
export const LICENSE_FINGERPRINTS = [
  [/GNU AFFERO GENERAL PUBLIC LICENSE/i, "AGPL-3.0"],
  [/GNU LESSER GENERAL PUBLIC LICENSE/i, "LGPL"],
  [/GNU GENERAL PUBLIC LICENSE\s+Version 3/i, "GPL-3.0"],
  [/GNU GENERAL PUBLIC LICENSE\s+Version 2/i, "GPL-2.0"],
  [/Mozilla Public License Version 2\.0/i, "MPL-2.0"],
  [/Apache License\s+Version 2\.0/i, "Apache-2.0"],
  [/Permission is hereby granted, free of charge, to any person obtaining a copy/i, "MIT"],
  [/Permission to use, copy, modify, and\/or distribute this software/i, "ISC"],
  // BSD-2-Clause and BSD-3-Clause share this exact preamble verbatim — resolved
  // below by checking for the extra "endorse or promote" clause BSD-3 alone carries.
  [/Redistribution and use in source and binary forms/i, "BSD"],
  [/This is free and unencumbered software released into the public domain/i, "Unlicense"],
];

const BSD3_ENDORSEMENT_CLAUSE = /may be used to endorse or promote products derived from this software/i;

/** Name the license a blob of text actually IS. Never guesses from a filename. */
export function identifyLicenseText(text) {
  if (typeof text !== "string" || text.trim() === "") return "EMPTY";
  const flat = text.replace(/\s+/g, " ");
  for (const [re, id] of LICENSE_FINGERPRINTS) {
    if (!re.test(flat)) continue;
    if (id === "BSD") return BSD3_ENDORSEMENT_CLAUSE.test(flat) ? "BSD-3-Clause" : "BSD-2-Clause";
    return id;
  }
  return "UNRECOGNIZED";
}

/** Normalize a declaration for comparison. A compound SPDX expression escalates. */
export function normalizeDeclared(decl) {
  if (!decl || typeof decl !== "string") return null;
  const d = decl.trim();
  if (d === "") return null;
  if (/\s(OR|AND)\s/i.test(d) || d.startsWith("(")) return { expression: d };
  const id = d
    .replace(/-only$|-or-later$/i, "")
    .replace(/^GPL-2\.0.*$/i, "GPL-2.0")
    .replace(/^LGPL-.*$/i, "LGPL");
  return { id };
}

/** The verdict. Every non-ok path names WHY. */
export function declarationMatches(declared, shippedId) {
  const n = normalizeDeclared(declared);
  if (!n) return { ok: false, reason: "no-declaration" };
  if (n.expression) return { ok: false, reason: "spdx-expression-needs-human" };
  const shipped = String(shippedId).replace(/^GPL-2\.0.*$/i, "GPL-2.0");
  if (shipped === "EMPTY") return { ok: false, reason: "license-file-empty" };
  if (shipped === "NO-LICENSE-FILE") return { ok: false, reason: "license-file-missing" };
  if (shipped === "UNREADABLE") return { ok: false, reason: "license-file-unreadable" };
  if (shipped === "UNRECOGNIZED") return { ok: false, reason: "license-text-unrecognized" };
  return n.id === shipped ? { ok: true } : { ok: false, reason: "declared-vs-shipped-divergence" };
}

export const MANIFEST_RE = /(^|\/)(package\.json|pyproject\.toml|Cargo\.toml|[^/]+\.gemspec)$/;
export const LICENSE_FILE_RE = /(^|\/)(LICEN[CS]E|COPYING)(\.(md|txt|rst))?$/i;
export const VENDOR_RE = /(^|\/)(node_modules|vendor|third_party|\.venv|target|dist|fixtures?|testdata)(\/|$)/;

const pyName = (t) => t.match(/^\s*name\s*=\s*["']([^"']+)["']/mi)?.[1] ?? null;

/** Read a manifest's license DECLARATION plus enough context to judge it. */
export function parseManifest(path, text) {
  try {
    if (path.endsWith("package.json")) {
      const j = JSON.parse(text);
      return {
        declared: typeof j.license === "string" ? j.license : null,
        private: j.private === true,
        name: j.name ?? null,
        ecosystem: "npm",
        files: Array.isArray(j.files) ? j.files : null,
      };
    }
    if (path.endsWith("pyproject.toml")) {
      const block = text.match(/^\s*license\s*=\s*(.+)$/mi)?.[1] ?? "";
      const classifier = text.match(/License :: OSI Approved :: ([^"'\]]+?) License/i)?.[1]?.trim() ?? null;
      if (/file\s*=/.test(block)) return { declared: null, classifier, private: false, name: pyName(text), ecosystem: "pypi", licenseByFile: true };
      const declared = block.match(/text\s*=\s*["']([^"']+)["']/)?.[1] ?? block.match(/^["']([^"']+)["']/)?.[1] ?? null;
      return { declared, classifier, private: false, name: pyName(text), ecosystem: "pypi" };
    }
    if (path.endsWith("Cargo.toml")) {
      // A virtual workspace root ships nothing itself.
      if (/^\s*\[workspace\]/m.test(text) && !/^\s*\[package\]/m.test(text)) return { declared: null, private: true, name: null, ecosystem: "cargo" };
      const excludeMatch = text.match(/^\s*exclude\s*=\s*\[([^\]]*)\]/mi)?.[1] ?? "";
      const includeMatch = text.match(/^\s*include\s*=\s*\[([^\]]*)\]/mi)?.[1] ?? null;
      return {
        declared: text.match(/^\s*license\s*=\s*["']([^"']+)["']/mi)?.[1] ?? null,
        private: /^\s*publish\s*=\s*false/mi.test(text),
        name: text.match(/^\s*name\s*=\s*["']([^"']+)["']/mi)?.[1] ?? null,
        ecosystem: "cargo",
        excludesLicense: /LICEN[CS]E/i.test(excludeMatch),
        include: includeMatch,
      };
    }
    if (path.endsWith(".gemspec")) {
      const filesMatch = text.match(/\.files\s*=\s*\[([^\]]*)\]/)?.[1] ?? null;
      return {
        declared: text.match(/\.licenses?\s*=\s*\[?\s*["']([^"']+)["']/)?.[1] ?? null,
        private: false,
        name: text.match(/\.name\s*=\s*["']([^"']+)["']/)?.[1] ?? null,
        ecosystem: "rubygems",
        files: filesMatch,
      };
    }
  } catch { return null; }
  return null;
}

/**
 * Find the LICENSE that would actually travel with a manifest.
 *
 * `strict: true` models npm/cargo, which pack the LICENSE from the PACKAGE
 * directory and never walk up to a repo root. Always strict here: every
 * dispatch-edge subpackage must carry its own copy.
 */
export function resolveShippedLicense(manifestPath, licensePaths, { strict = true } = {}) {
  const dirOf = (p) => (p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "");
  let dir = dirOf(manifestPath);
  for (;;) {
    const hit = licensePaths.find((L) => dirOf(L) === dir);
    if (hit) return hit;
    if (strict || dir === "") return null;
    dir = dirOf(dir);
  }
}
