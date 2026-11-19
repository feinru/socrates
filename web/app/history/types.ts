import type { Message } from "../chat/types";

export type { Message };

export interface HistoryItem {
  id: string;
  date: string;
  preview: string;
  messages: Message[];
}
