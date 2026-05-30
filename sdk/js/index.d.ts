// Type declarations for @wave-av/dispatch — the JS/TS client for wave Dispatch.
// Hand-written to match index.js exactly (the JS is the source of truth). A WAVE product.

/** Routing decision returned by `route` / `execute` / `routeVector` (POST `/`). */
export interface Decision {
  /** Chosen route/label (e.g. "local_search", "claude_reason"). */
  route: string;
  /** Classifier probability for the chosen route. */
  probability: number;
  /** Margin between the top two routes. */
  margin: number;
  /** True => escalate to your frontier model rather than handle locally. */
  forward: boolean;
  /** Edge-local answer; present only when `execute` is requested and your plan enables it. */
  answer?: string;
  executed_by?: string;
  decided_at?: string;
  tier?: string;
  /** Forward-compatible: the worker may add fields. */
  [k: string]: unknown;
}

/** This license's savings ledger summary (`GET /ledger/summary`). */
export interface Savings {
  decisions?: number;
  local_handled?: number;
  escalated?: number;
  saved_usd?: number;
  saved_pct?: number;
  [k: string]: unknown;
}

/** This license's agent-subscription status (`GET /subscription/status`). */
export interface Subscription {
  plan?: string;
  quota?: number;
  used?: number;
  remaining?: number;
  renews_at?: string;
  [k: string]: unknown;
}

/** Programmatic subscription plans accepted by `subscribe`. */
export type Plan = "agent_starter" | "agent_pro" | "agent_scale";

/** The x402-style 402 challenge body handed to a {@link PaymentHook}. */
export interface PaymentChallenge {
  accepts?: Array<Record<string, unknown>>;
  [k: string]: unknown;
}

/**
 * Called once with the 402 challenge body; returns the headers to retry the request with
 * (e.g. `{ "x-payment": "..." }` for x402, `{ "cdp-payment": "..." }` for CDP). 0.5.0+.
 */
export type PaymentHook = (
  challenge: PaymentChallenge
) => Promise<Record<string, string>> | Record<string, string>;

/** Minimal `fetch` shape the client depends on (lets you inject a custom implementation). */
export type FetchImpl = (
  url: string,
  init: {
    method: string;
    headers: Record<string, string>;
    body?: string;
  }
) => Promise<{
  ok: boolean;
  status: number;
  json(): Promise<any>;
  text(): Promise<string>;
}>;

/** Options for the {@link Dispatch} constructor. */
export interface DispatchOptions {
  /** Stateless edge endpoint. Defaults to `https://dispatch.wave.online`. */
  endpoint?: string;
  /** Stateful sidecar (savings + subscriptions). Defaults to `https://dispatch-agents.wave.online`. */
  agentsEndpoint?: string;
  /** Custom `fetch`; defaults to `globalThis.fetch`. */
  fetchImpl?: FetchImpl;
  /** Auto-pay on 402 by signing the challenge and resubmitting once. 0.5.0+. */
  paymentHook?: PaymentHook;
}

/** Wallet providers with a built-in signing factory ({@link Dispatch.walletHook}). */
export type WalletProvider = "cdp" | "privy" | "bridge" | "custom";

/**
 * Provider-specific credentials. snake_case is canonical (matches the Python/Ruby/Go/Rust SDKs and
 * the JWT payload field names that flow into `kid`). camelCase aliases are still accepted in
 * 0.6.3+ for backward-compat with 0.5.x–0.6.2 JS callers; snake_case wins if both are present.
 *
 *   cdp:     `{ api_key, api_secret, address?, network? }`   (aliases: apiKey, apiSecret)
 *   privy:   `{ app_id, app_secret, wallet_id }`              (aliases: appId, appSecret, walletId)
 *   bridge:  `{ api_key, source_wallet?, destination? }`      (aliases: apiKey, sourceWallet)
 */
export type CdpCredentials =
  | { api_key: string; api_secret: string; address?: string; network?: string }
  | { apiKey: string; apiSecret: string; address?: string; network?: string };
export type PrivyCredentials =
  | { app_id: string; app_secret: string; wallet_id: string }
  | { appId: string; appSecret: string; walletId: string };
export type BridgeCredentials =
  | { api_key: string; source_wallet?: string; destination?: string }
  | { apiKey: string; sourceWallet?: string; destination?: string };

/** Configuration for {@link Dispatch.walletHook}. */
export interface WalletHookConfig {
  provider: WalletProvider;
  /** Provider-specific credentials. See {@link CdpCredentials} / {@link PrivyCredentials} / {@link BridgeCredentials}. */
  credentials?: CdpCredentials | PrivyCredentials | BridgeCredentials | Record<string, unknown>;
  /** Required when `provider` is "custom": your own `(challenge) => headers`. */
  sign?: (challenge: PaymentChallenge) => Promise<Record<string, string>> | Record<string, string>;
  fetchImpl?: FetchImpl;
}

/** Client for the wave Dispatch edge API. */
export declare class Dispatch {
  license?: string;
  endpoint: string;
  /** Resolved stateful-sidecar base URL. */
  agents: string;
  fetch: FetchImpl;
  paymentHook?: PaymentHook;

  /**
   * @param license Bearer license key (`wv_...`); omit for x402 pay-per-use.
   * @param opts    Endpoints, custom fetch, and/or a payment hook.
   */
  constructor(license?: string, opts?: DispatchOptions);

  /** Classify a prompt (no execution). Sovereign tier: pass `profile` (Fast|Expert|Heavy|Code). */
  route(prompt: string, profile?: string): Promise<Decision>;
  /** Classify and run on the edge if your plan allows it. Optional `profile` as in {@link route}. */
  execute(prompt: string, profile?: string): Promise<Decision>;
  /** Classify a pre-computed 768-d embedding (matmul-only: cheapest + fastest). */
  routeVector(vector: number[], profile?: string): Promise<Decision>;

  /** This license's savings ledger. Requires a license. */
  savings(): Promise<Savings>;
  /** This license's agent-subscription status. Requires a license. */
  subscription(): Promise<Subscription>;
  /** Start/replace a programmatic subscription. Requires a license. */
  subscribe(plan: Plan): Promise<Subscription>;

  /** Build a {@link PaymentHook} that signs each 402 challenge via a wallet provider. 0.5.0+. */
  static walletHook(cfg: WalletHookConfig): PaymentHook;
  /** Low-level CDP-JWT signer (ES256 / P-256) for power users driving CDP directly. 0.6.0+. */
  static signCdpJwt(
    creds: CdpCredentials,
    accept: Record<string, unknown>
  ): Promise<string>;
}

export default Dispatch;
