"use client";

import { useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import styles from "../page.module.css";
import { Message, ProcessStep } from "./types";
import { normalizeMarkdown, formatUriLabel } from "./format";

/** A labelled, copyable code block; the same look in answers and in the process panel. */
function CodeBlock({ label, code }: { label: string; code: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <div className={styles.codeContainer}>
      <div className={styles.codeHeader}>
        <span>{label}</span>
        <button type="button" className={styles.copyCodeButton} onClick={copy}>
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className={styles.codePre}>
        <code>{code}</code>
      </pre>
    </div>
  );
}

const TOOL_VERBS: Record<string, string> = {
  search_security_vectors: "Searched",
  execute_sparql_query: "Queried graph",
};

/** One readable line for a step's input: the search text, or what a SPARQL query checks. */
function stepLine(step: ProcessStep): string {
  if (step.tool !== "execute_sparql_query") return step.input;
  // Each technique repeats once per subquery in the link check: count it once.
  const techniques = [...new Set([...step.input.matchAll(/resource\/attack\/(T\d{4}(?:\.\d{3})?)/g)].map((m) => m[1]))];
  if (/GROUP_CONCAT/i.test(step.input) && techniques.length) {
    const shown = techniques.slice(0, 3).join(", ");
    return `Link check: ${shown}${techniques.length > 3 ? ` +${techniques.length - 3}` : ""}`;
  }
  const firstLine = step.input
    .split("\n")
    .map((l) => l.trim())
    .find((l) => l && !/^(PREFIX|DEFINE)\b/i.test(l));
  return firstLine || "SPARQL query";
}

/** Short outcome for the row's right side: "5 results", "1 row", "failed". */
function stepOutcome(step: ProcessStep): string {
  if (step.status === "running") return "";
  if (step.status === "error") return "failed";
  return (step.summary || "").split(":")[0];
}

/** Header sentence, e.g. "Searched the knowledge base twice, ran a SPARQL query". */
function describeSteps(steps: ProcessStep[]): string {
  const count = (tool: string) => steps.filter((s) => s.tool === tool).length;
  const times = (n: number) => (n === 1 ? "" : n === 2 ? " twice" : ` ${n} times`);
  const parts: string[] = [];
  const searches = count("search_security_vectors");
  const queries = count("execute_sparql_query");
  if (searches) parts.push(`searched the knowledge base${times(searches)}`);
  if (queries) parts.push(queries === 1 ? "ran a SPARQL query" : `ran ${queries} SPARQL queries`);
  const text = parts.join(", ");
  return text ? text[0].toUpperCase() + text.slice(1) : "No tools used";
}

interface ProcessPanelProps {
  steps: ProcessStep[];
  /** While the agent is working: open, with the current status as the header. */
  live?: boolean;
  status?: string;
}

/** The agent's tool calls as compact rows; each row expands to the exact query and result. */
export function ProcessPanel({ steps, live = false, status }: ProcessPanelProps) {
  if (!live && !steps.length) return null;
  const header = live ? status || "Working…" : describeSteps(steps);
  return (
    <details className={styles.processPanel} open={live || undefined}>
      <summary className={`${styles.processHeader} ${live ? styles.processLive : ""}`}>{header}</summary>
      {steps.length ? (
        <ul className={styles.processSteps}>
          {steps.map((step) => (
            <li key={step.id} className={styles[`step_${step.status}`]}>
              <details>
                <summary className={styles.stepRow}>
                  <span className={styles.stepVerb}>{TOOL_VERBS[step.tool] || step.tool}</span>
                  <span className={styles.stepText} title={stepLine(step)}>
                    {stepLine(step)}
                  </span>
                  <span className={styles.stepOutcome}>
                    {step.status === "running" ? <span className={styles.stepSpinner} aria-label="running" /> : stepOutcome(step)}
                  </span>
                </summary>
                <div className={styles.stepDetails}>
                  <CodeBlock
                    label={step.tool === "execute_sparql_query" ? "SPARQL" : "SEARCH QUERY"}
                    code={step.input}
                  />
                  {step.summary && step.status === "error" ? <CodeBlock label="ERROR" code={step.summary} /> : null}
                  {step.preview ? <CodeBlock label="RESULT" code={step.preview} /> : null}
                </div>
              </details>
            </li>
          ))}
        </ul>
      ) : null}
    </details>
  );
}

interface MessageItemProps {
  message: Message;
}

export function MessageItem({ message }: MessageItemProps) {
  if (message.role === "user") {
    return (
      <div className={`${styles.message} ${styles.messageUser}`}>
        <div className={styles.messageIndicator}>&lt;</div>
        <div className={styles.messageContent}>{message.content}</div>
      </div>
    );
  }

  const content = normalizeMarkdown(message.content);

  return (
    <div className={`${styles.message} ${styles.messageAgent}`}>
      <div className={styles.messageIndicator}>&gt;</div>
      <div className={styles.messageContent}>
        {message.steps?.length ? <ProcessPanel steps={message.steps} /> : null}
        <div className={styles.markdownOutput}>
          <ReactMarkdown
            remarkPlugins={[remarkGfm]}
            components={{
              table({ children }) {
                return (
                  <div className={styles.tableWrapper}>
                    <table>{children}</table>
                  </div>
                );
              },
              pre({ children }) {
                return <div className={styles.codeBlockWrapper}>{children}</div>;
              },
              code({ className, children, ...props }) {
                const match = /language-(\w+)/.exec(className || "");
                const codeString = String(children).replace(/\n$/, "");
                const isBlock = Boolean(match) || codeString.includes("\n");

                if (isBlock) {
                  return <CodeBlock label={match ? match[1].toUpperCase() : "SPARQL"} code={codeString} />;
                }
                return <code className={styles.inlineCode} {...props}>{children}</code>;
              },
              a({ href, children }) {
                const url = href || "";
                if (url.includes("w3id.org/sepses") || url.includes("d3fend.mitre.org")) {
                  return <code className={styles.uriBadge} title={url}>{formatUriLabel(url)}</code>;
                }
                return <a href={url} target="_blank" rel="noopener noreferrer">{children}</a>;
              },
            }}
          >
            {content}
          </ReactMarkdown>
        </div>
      </div>
    </div>
  );
}
