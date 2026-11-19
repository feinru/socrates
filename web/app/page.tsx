"use client";

import { useState, useRef, useEffect, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { v4 as uuidv4 } from "uuid";
import styles from "./page.module.css";
import { ChatEvent, Message, ProcessStep } from "./chat/types";
import { MessageItem, ProcessPanel } from "./chat/message";
import { ChatInput } from "./chat/input";
import { loadSessionMessages, saveSessionMessages } from "./chat/session";

const INITIAL_MESSAGE: Message = {
  id: "init",
  role: "agent",
  content: "Hello, I am your Cybersecurity Knowledge Graph Assistant. Ask me anything about CVEs, attack patterns, defenses, or vulnerabilities.",
};

function ChatApp() {
  const [messages, setMessages] = useState<Message[]>([INITIAL_MESSAGE]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  // Live view of the agent's work while it runs.
  const [liveSteps, setLiveSteps] = useState<ProcessStep[]>([]);
  const [liveStatus, setLiveStatus] = useState("");
  const [sessionId, setSessionId] = useState("");
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const searchParams = useSearchParams();

  useEffect(() => {
    const session = searchParams.get("session");
    if (session) {
      setSessionId(session);
      const saved = loadSessionMessages(session);
      if (saved) setMessages(saved);
    } else {
      setSessionId(uuidv4());
      setMessages([INITIAL_MESSAGE]);
    }
  }, [searchParams]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, isLoading, liveSteps, liveStatus]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || isLoading) return;
    const userMsg: Message = { id: uuidv4(), role: "user", content: input.trim() };
    const newMessages = [...messages, userMsg];
    setMessages(newMessages);
    setInput("");
    setIsLoading(true);

    setLiveSteps([]);
    setLiveStatus("Sending question…");
    let steps: ProcessStep[] = [];
    const updateSteps = (next: ProcessStep[]) => {
      steps = next;
      setLiveSteps(next);
    };

    try {
      // Slightly longer than the server's own 180s agent timeout.
      const res = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ messages: newMessages }),
        signal: AbortSignal.timeout(210_000),
      });
      if (!res.ok || !res.body) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || err.message || `HTTP ${res.status}`);
      }

      // The server streams one JSON event per line.
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let final: string | null = null;
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";
        for (const line of lines) {
          if (!line.trim()) continue;
          const event = JSON.parse(line) as ChatEvent;
          if (event.type === "status") setLiveStatus(event.text);
          else if (event.type === "step") updateSteps([...steps, event.step]);
          else if (event.type === "result")
            updateSteps(
              steps.map((st) =>
                st.id === event.id
                  ? { ...st, status: event.status, summary: event.summary, preview: event.preview }
                  : st
              )
            );
          else if (event.type === "final") final = event.response;
          else if (event.type === "error") throw new Error(event.error);
        }
      }
      if (final === null) throw new Error("The connection closed before the answer arrived.");

      const agentMsg: Message = { id: uuidv4(), role: "agent", content: final, steps };
      const updated = [...newMessages, agentMsg];
      setMessages(updated);
      saveSessionMessages(sessionId, updated);
    } catch (error: unknown) {
      const err = error as Error;
      const text =
        err.name === "TimeoutError"
          ? "The server did not respond in time."
          : /network ?error|failed to fetch|load failed/i.test(err.message)
            ? "The connection to the server was lost (it may have restarted). Please send your question again."
            : err.message;
      const errorMsg: Message = { id: uuidv4(), role: "agent", content: `Error: ${text}`, steps };
      setMessages([...newMessages, errorMsg]);
    } finally {
      setIsLoading(false);
      setLiveSteps([]);
      setLiveStatus("");
    }
  };

  return (
    <>
      <div className={styles.chatContainer}>
        {messages.map((m) => <MessageItem key={m.id} message={m} />)}
        {isLoading && (
          <div className={`${styles.message} ${styles.messageAgent}`}>
            <div className={styles.messageIndicator}>&gt;</div>
            <div className={styles.messageContent}>
              <ProcessPanel steps={liveSteps} live status={liveStatus} />
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>
      <ChatInput input={input} setInput={setInput} onSubmit={handleSubmit} isLoading={isLoading} />
    </>
  );
}

export default function Page() {
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <ChatApp />
    </Suspense>
  );
}
