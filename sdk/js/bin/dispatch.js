#!/usr/bin/env node
// `npx @wave-av/dispatch wallet` — JS parity of the Python `dispatch wallet` onboarding.
// Layers over the existing SDK walletHook (index.js); does NOT reimplement signing. Testnet-default;
// --mainnet (real money) must be explicit. Never moves funds — configures a hook + checks reachability.
import { writeFileSync, mkdirSync, existsSync, readFileSync, chmodSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const CONFIG = join(homedir(), ".wave", "wallet.json");
const ENDPOINT = (process.env.WAVE_ENDPOINT || "https://dispatch.wave.online").replace(/\/+$/, "");
const PROVIDERS = ["cdp", "privy", "bridge", "custom"];
const CRED_ENV = {
  cdp: ["CDP_API_KEY", "CDP_API_SECRET", "CDP_ADDRESS"],
  privy: ["PRIVY_APP_ID", "PRIVY_APP_SECRET", "PRIVY_WALLET_ID"],
  bridge: ["BRIDGE_API_KEY", "BRIDGE_SOURCE_WALLET"],
  custom: [],
};

async function payments() {
  try { const r = await fetch(ENDPOINT + "/payments"); return await r.json(); }
  catch (e) { return { _error: String(e) }; }              // honest: surface failure, never fake
}

function setup(args) {
  const provider = args[args.indexOf("--provider") + 1];
  const mainnet = args.includes("--mainnet");
  if (!PROVIDERS.includes(provider)) {
    console.log(`usage: npx @wave-av/dispatch wallet setup --provider ${PROVIDERS.join("|")} [--mainnet]`);
    console.log("  testnet (base-sepolia) is the default; --mainnet moves REAL money and must be explicit.");
    return;
  }
  const network = mainnet ? "base" : "base-sepolia";
  if (mainnet) console.log("⚠️  MAINNET selected — configures the wallet to settle with REAL USDC on Base.");
  const cfg = { provider, network, endpoint: ENDPOINT, credentials_env: CRED_ENV[provider] };
  mkdirSync(join(homedir(), ".wave"), { recursive: true });
  writeFileSync(CONFIG, JSON.stringify(cfg, null, 2));
  chmodSync(CONFIG, 0o600);                                 // creds-adjacent config: owner-only
  console.log(`✓ wallet configured: provider=${provider} network=${network} → ${CONFIG}`);
  console.log("  Secrets stay in env vars (never written to disk):", cfg.credentials_env.join(", ") || "(custom: you sign)");
  console.log("\nUse it (JS):");
  console.log("  import Dispatch from '@wave-av/dispatch';");
  console.log(`  const hook = Dispatch.walletHook({ provider: '${provider}', credentials: { /* from env */ } });`);
  console.log("  const client = new Dispatch(undefined, { paymentHook: hook });  // auto-pays 402");
  console.log(`  await client.route('summarize this');                          // settles on ${network}`);
}

async function status() {
  if (!existsSync(CONFIG)) { console.log("no wallet configured. run: npx @wave-av/dispatch wallet setup --provider cdp|privy|bridge"); return; }
  const cfg = JSON.parse(readFileSync(CONFIG, "utf8"));
  console.log(`provider=${cfg.provider} network=${cfg.network} endpoint=${cfg.endpoint}`);
  const miss = (cfg.credentials_env || []).filter((v) => !process.env[v]);
  if (miss.length) console.log("  creds MISSING (env):", miss.join(", "));
  const p = await payments();
  console.log(p._error ? "  /payments unreachable: " + p._error
    : `  /payments ok — pay_per_use_enabled=${p.pay_per_use_enabled} protocols=${JSON.stringify(p.protocols)}`);
}

const [sub, cmd, ...rest] = process.argv.slice(2);
if (sub !== "wallet") { console.log("usage: npx @wave-av/dispatch wallet setup|status"); process.exit(0); }
if (cmd === "setup") setup(rest);
else if (cmd === "status") await status();
else console.log("usage: npx @wave-av/dispatch wallet setup --provider cdp|privy|bridge [--mainnet]  |  wallet status");
