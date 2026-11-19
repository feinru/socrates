// Deterministic grounding check: every security identifier in the final answer
// must have appeared in a tool result (or in the user's own messages). The model
// is told this in the prompt, but prompts are not guarantees.

// LLMs often emit non-ASCII hyphens (U+2010-2015, U+2212), e.g. "CWE‑287".
const DASHES = /[‐-―−]/g;
// Also ATT&CK mitigations (M####), software (S####) and groups (G####).
const ID_PATTERN = /\b(CVE-\d{4}-\d{4,}|CWE-\d+|CAPEC-\d+|T\d{4}(?:\.\d{3})?|[MSG]\d{4}|D3A?-[A-Z0-9]+)\b/g;

export function extractIds(text: string): Set<string> {
  const normalized = text.replace(DASHES, "-").toUpperCase();
  return new Set(normalized.match(ID_PATTERN) ?? []);
}

/** IDs mentioned in `answer` that appear in none of the `sources`. */
export function findUngroundedIds(answer: string, sources: string[]): string[] {
  const allowed = new Set<string>();
  for (const s of sources) for (const id of extractIds(s)) allowed.add(id);
  return [...extractIds(answer)].filter((id) => !allowed.has(id)).sort();
}

/** Start of the note appended to answers; used to strip it from history. */
export const GROUNDING_NOTE_MARKER = "\n\n---\n**Grounding check:**";

/**
 * An earlier answer as a grounding source: its IDs count as known, except the
 * ones its own grounding note flagged (those stay unverified on later turns).
 */
export function priorAnswerSource(answer: string): string {
  const [body, note = ""] = answer.split(GROUNDING_NOTE_MARKER);
  const flagged = extractIds(note);
  let text = body.replace(DASHES, "-").toUpperCase();
  for (const id of flagged) text = text.split(id).join(" ");
  return text;
}

export function groundingNote(ungrounded: string[]): string {
  if (!ungrounded.length) return "";
  return (
    `${GROUNDING_NOTE_MARKER} ${ungrounded.join(", ")} ` +
    `${ungrounded.length === 1 ? "does" : "do"} not appear in any knowledge-graph result for this question. ` +
    "Treat any statement about " + (ungrounded.length === 1 ? "it" : "them") + " as unverified."
  );
}
