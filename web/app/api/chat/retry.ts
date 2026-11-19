// LangChain's default retry handler stops on any 429 whose message mentions
// "billing". Groq's per-minute limit errors always link to the billing page, so
// they were never retried. This handler waits the time Groq asks for instead.

import { AsyncLocalStorage } from "node:async_hooks";

const MAX_WAIT_MS = 60_000;

/** Per-request callback so rate-limit waits can be shown to the user live. */
export const progressNotifier = new AsyncLocalStorage<(text: string) => void>();

/** Milliseconds to wait before retrying, or null if the error should not be retried. */
export function groqRetryDelayMs(error: unknown): number | null {
  const e = error as { status?: number; response?: { status?: number }; message?: string };
  const status = e?.status ?? e?.response?.status;
  const msg = e?.message || "";
  if (status !== 429) return null;
  // Daily limits won't clear in time; only per-minute windows are worth waiting for.
  if (/per day|\b(TPD|RPD)\b/i.test(msg)) return null;
  if (!/per minute|\b(TPM|RPM)\b/i.test(msg)) return null;
  const m = /try again in (?:(\d+)m)?([\d.]+)s/i.exec(msg);
  const waitMs = m ? (Number(m[1] || 0) * 60 + Number(m[2])) * 1000 + 500 : 10_000;
  return Math.min(waitMs, MAX_WAIT_MS);
}

export async function groqOnFailedAttempt(error: unknown): Promise<void> {
  const delay = groqRetryDelayMs(error);
  if (delay === null) throw error;
  console.log(`[chat] Groq per-minute limit hit; waiting ${(delay / 1000).toFixed(1)}s before retrying`);
  progressNotifier.getStore()?.(`Rate limit reached, waiting ${Math.ceil(delay / 1000)}s before continuing…`);
  await new Promise((resolve) => setTimeout(resolve, delay));
}
