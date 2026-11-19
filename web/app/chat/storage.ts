// Chat history lives in the browser's localStorage under one key.
const HISTORY_KEY = "socrates_chat_history";
// Key used before the project was renamed to SOCrates; migrated on first read.
const LEGACY_HISTORY_KEY = "cskg_chat_history";

export function readHistoryRaw(): string | null {
  const current = localStorage.getItem(HISTORY_KEY);
  if (current !== null) return current;
  const legacy = localStorage.getItem(LEGACY_HISTORY_KEY);
  if (legacy !== null) {
    localStorage.setItem(HISTORY_KEY, legacy);
    localStorage.removeItem(LEGACY_HISTORY_KEY);
  }
  return legacy;
}

export function writeHistoryRaw(value: string): void {
  localStorage.setItem(HISTORY_KEY, value);
}
