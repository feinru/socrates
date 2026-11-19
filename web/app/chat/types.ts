export interface ProcessStep {
  id: string;
  tool: string;
  /** What the agent asked for: the search query or the SPARQL text. */
  input: string;
  status: "running" | "done" | "error";
  /** One-line outcome, e.g. "5 results: T1461, T1636.005". */
  summary?: string;
  /** Compact view of the raw result, shown when the step is expanded. */
  preview?: string;
}

export interface Message {
  id: string;
  role: "user" | "agent";
  content: string;
  /** The agent's tool calls for this answer, shown in a collapsible panel. */
  steps?: ProcessStep[];
}

export interface ChatSession {
  preview: string;
  date: string;
  messages: Message[];
}

/** Events streamed by /api/chat, one JSON object per line. */
export type ChatEvent =
  | { type: "status"; text: string }
  | { type: "step"; step: ProcessStep }
  | { type: "result"; id: string; status: "done" | "error"; summary: string; preview: string }
  | { type: "final"; response: string; ungrounded: string[] }
  | { type: "error"; error: string };
