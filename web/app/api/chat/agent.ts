// Agent setup and execution, separate from the route so it can be tested
// with a scripted model (Next.js route files may only export HTTP handlers).
import { ChatGroq } from "@langchain/groq";
import type { BaseChatModel } from "@langchain/core/language_models/chat_models";
import { createReactAgent } from "@langchain/langgraph/prebuilt";
import { AIMessage, HumanMessage, SystemMessage } from "@langchain/core/messages";
import { SYSTEM_PROMPT } from "./prompt";
import { groqOnFailedAttempt } from "./retry";
import { stepInput, summarizeResult } from "./steps";
import type { ChatEvent } from "../../chat/types";
import { findUngroundedIds, groundingNote, priorAnswerSource } from "./grounding";
import { preRetrieve } from "./retrieval";

// Hard ceiling for one question, so the UI never waits forever on the LLM.
// Generous enough to wait out a per-minute token window on small-tier plans.
const AGENT_TIMEOUT_MS = Number(process.env.AGENT_TIMEOUT_MS || 180_000);
// Each step is one LLM call or one tool call; LangGraph's default is 25,
// which can burn through a small quota on a single question.
const AGENT_RECURSION_LIMIT = Number(process.env.AGENT_RECURSION_LIMIT || 14);
// Budget for tool output passed to the forced final answer (Groq free: ~8K tokens/min).
const FALLBACK_CONTEXT_CHARS = 9_000;
// Failed tool calls tolerated before answering from what was gathered.
const MAX_FAILED_CALLS = 2;

// Output cap for Groq; counted against its per-minute budget up front.
const GROQ_MAX_TOKENS = Number(process.env.GROQ_MAX_TOKENS || 2200);
// Groq free tier: 8K tokens/minute per model (input + max output). Keep a margin.
const GROQ_TPM_BUDGET = Number(process.env.GROQ_TPM_BUDGET || 7600);

/** Rough token estimate (~3.5 characters per token for this English/JSON mix). */
function estimateTokens(texts: string[]): number {
  return Math.ceil(texts.reduce((n, t) => n + t.length, 0) / 3.5);
}

/** The chat model (Groq). Returns an error message if GROQ_API_KEY is missing. */
export function createModel(): { llm: BaseChatModel; label: string } | { error: string } {
  if (!process.env.GROQ_API_KEY) return { error: "GROQ_API_KEY is not set in the environment" };
  const model = process.env.GROQ_MODEL || "qwen/qwen3.8-27b";
  const llm = new ChatGroq({
    model,
    temperature: 0,
    // Groq's free tier allows ~8K tokens/minute: cap output and reasoning so a
    // multi-step question fits. Raise via env if your plan allows more.
    // Groq counts max_tokens against the per-minute budget up front, so keep it modest.
    maxTokens: GROQ_MAX_TOKENS,
    // Reasoning tokens count toward the same budget. gpt-oss: low effort. Qwen 3:
    // thinking off by default (retrieval is done in code, the model mainly writes);
    // set GROQ_REASONING_EFFORT=default to enable it.
    ...(model.startsWith("openai/gpt-oss")
      ? { reasoningEffort: (process.env.GROQ_REASONING_EFFORT || "low") as "low" | "medium" | "high" }
      : model.startsWith("qwen/")
        ? { reasoningEffort: (process.env.GROQ_REASONING_EFFORT || "none") as "none" | "default" }
        : {}),
    // A per-minute 429 clears within seconds ("try again in Ns"): wait and retry.
    // Rejected requests use no tokens. See retry.ts for why the default handler can't.
    maxRetries: Number(process.env.GROQ_MAX_RETRIES || 4),
    onFailedAttempt: groqOnFailedAttempt,
  });
  // Not a constructor option in @langchain/groq, but sent with every request:
  // keep any reasoning out of the answer text (Qwen otherwise inlines <think> tags).
  if (model.startsWith("qwen/")) llm.reasoningFormat = "hidden";
  return { llm, label: `groq:${model}` };
}

function messageText(m: { content: unknown }): string {
  const raw =
    typeof m.content === "string"
      ? m.content
      : Array.isArray(m.content)
        ? (m.content as { text?: string }[]).map((b) => b.text || "").join("")
        : "";
  // Backstop for reasoning models that inline their thinking.
  return raw.replace(/<think>[\s\S]*?<\/think>\s*/g, "");
}

/** When the step budget runs out, answer from the tool results gathered so far
 *  instead of failing. Tool output is passed as plain text, so no tools are bound. */
async function forceFinalAnswer(
  llm: BaseChatModel,
  messages: AIMessage[],
  signal: AbortSignal
): Promise<string> {
  const question = [...messages].reverse().find((m) => m.getType() === "human");
  let context = messages
    .filter((m) => m.getType() === "tool")
    .map((m) => `[${(m as unknown as { name?: string }).name || "tool"}] ${messageText(m)}`)
    .join("\n");
  if (context.length > FALLBACK_CONTEXT_CHARS) context = context.slice(-FALLBACK_CONTEXT_CHARS);
  const reply = await llm.invoke(
    [
      new SystemMessage(SYSTEM_PROMPT),
      new HumanMessage(
        `${question ? messageText(question) : ""}\n\nThe tool budget is used up; do not request tools. ` +
          `Write the final answer now using ONLY these tool results (say "No links in the knowledge graph" where SPARQL found none):\n${context}`
      ),
    ],
    { signal }
  );
  return messageText(reply);
}

export function describeError(error: unknown): { status: number; error: string } {
  const msg = (error as Error)?.message || String(error);
  const name = (error as Error)?.name || "";
  if (name === "AbortError" || name === "TimeoutError" || /aborted|timed? ?out/i.test(msg)) {
    return { status: 504, error: `The analysis took longer than ${AGENT_TIMEOUT_MS / 1000}s and was stopped. The LLM provider may be slow or rate-limited; try again later.` };
  }
  if (/413|request too large|tokens per minute|\bTPM\b/i.test(msg)) {
    return { status: 429, error: "The request exceeded the model's tokens-per-minute limit. Wait a minute and try again, or ask a narrower question." };
  }
  if (/429|quota|rate.?limit|resource.?exhausted/i.test(msg)) {
    return { status: 429, error: "LLM API quota exhausted or rate-limited. Wait for the quota to reset, or switch provider/model in .env." };
  }
  if (/recursion limit/i.test(msg)) {
    return { status: 500, error: `The agent needed more than ${AGENT_RECURSION_LIMIT} steps and was stopped. Try a more specific question.` };
  }
  return { status: 500, error: msg };
}

export type Agent = ReturnType<typeof createReactAgent>;

export async function runAgent(
  agent: Agent,
  llm: BaseChatModel,
  inputMessages: (HumanMessage | AIMessage)[],
  send: (event: ChatEvent) => void
): Promise<void> {
  const started = Date.now();
  const signal = AbortSignal.timeout(AGENT_TIMEOUT_MS);
  // Standard searches + link check run in code first; the model gets them as
  // tool results it already has and mainly writes the report.
  const question = [...inputMessages].reverse().find((m) => m.getType() === "human");
  const humans = inputMessages.filter((m) => m.getType() === "human");
  const previousQuestion = humans.length > 1 ? messageText(humans[humans.length - 2]) : undefined;
  const retrieved = await preRetrieve(question ? messageText(question) : "", send, previousQuestion);
  let messages = [...inputMessages, ...retrieved];

  // Keep the first model call inside the provider's per-minute token budget:
  // if retrieval plus history is too large, drop older conversation turns.
  const inputBudget = GROQ_TPM_BUDGET - GROQ_MAX_TOKENS;
  const estimate = () =>
    estimateTokens([
      SYSTEM_PROMPT,
      ...messages.map((m) => messageText(m) + JSON.stringify((m as AIMessage).tool_calls ?? "")),
    ]);
  if (estimate() > inputBudget && question) {
    messages = [question, ...retrieved];
    console.log("[chat] input over budget; older conversation turns dropped");
  }
  console.log(`[chat] estimated input ~${estimate()} tokens (budget ${inputBudget})`);
  send({ type: "status", text: retrieved.length ? "Writing the analysis…" : "Thinking…" });

  const events = await agent.stream(
    { messages },
    { streamMode: "values", recursionLimit: AGENT_RECURSION_LIMIT, signal }
  );

  let finalResponse = "";
  let finalMessages: AIMessage[] = [];
  let seen = messages.length;
  const toolNames = new Map<string, string>();
  // Guards against a model stuck on bad tool calls: stop and answer from what was
  // gathered if it repeats a call that already failed, or after MAX_FAILED_CALLS.
  const callSignature = new Map<string, string>();
  const failedCalls = new Set<string>();
  let stopReason = "";
  try {
    for await (const event of events) {
      const currentMessages = (event as unknown as { messages: AIMessage[] }).messages;
      finalMessages = currentMessages;
      const t = `+${Date.now() - started}ms`;
      // Several tool results can arrive in one update: handle every new message.
      for (const msg of currentMessages.slice(seen)) {
        if (msg.getType() === "ai" && msg.tool_calls?.length) {
          for (const call of msg.tool_calls) {
            const signature = `${call.name}:${JSON.stringify(call.args)}`;
            if (failedCalls.has(signature)) {
              stopReason = "the model repeated a tool call that had already failed";
              break;
            }
            const id = call.id || `${call.name}-${toolNames.size}`;
            callSignature.set(id, signature);
            toolNames.set(id, call.name);
            console.log(`[chat] ${t} tool call ${call.name} ${JSON.stringify(call.args).replace(/\s+/g, " ").slice(0, 300)}`);
            send({
              type: "step",
              step: { id, tool: call.name, input: stepInput(call.name, call.args), status: "running" },
            });
          }
        } else if (msg.getType() === "tool") {
          const id = (msg as unknown as { tool_call_id?: string }).tool_call_id || "";
          const text = messageText(msg);
          const result = summarizeResult(toolNames.get(id) || "", text);
          console.log(`[chat] ${t} tool result: ${result.summary}`);
          send({ type: "result", id, ...result });
          send({ type: "status", text: "Analysing the results…" });
          if (result.status === "error") {
            failedCalls.add(callSignature.get(id) || id);
            if (failedCalls.size >= MAX_FAILED_CALLS) stopReason = `${MAX_FAILED_CALLS} tool calls failed`;
          }
        } else if (msg.getType() === "ai") {
          finalResponse = messageText(msg);
        }
        if (stopReason) break;
      }
      seen = currentMessages.length;
      if (stopReason) break; // stops the agent before it runs the bad call
    }
  } catch (error) {
    const message = (error as Error)?.message || "";
    if (/recursion limit/i.test(message)) stopReason = `the step limit (${AGENT_RECURSION_LIMIT}) was reached`;
    // e.g. Groq 400 "tool call validation failed: attempted to call tool 'X' which was not in request.tools"
    else if (/tool_use_failed|tool call validation failed|not in request\.tools/i.test(message))
      stopReason = "the model produced an invalid tool call";
    else throw error;
  }
  if (stopReason) {
    console.log(`[chat] ${stopReason}; forcing a final answer from gathered results`);
    send({ type: "status", text: "Writing the answer from the results gathered so far…" });
    finalResponse = await forceFinalAnswer(llm, finalMessages, signal);
  }

  if (!finalResponse) {
    console.error("[chat] agent finished without a final answer");
    throw new Error("No final response from agent");
  }

  // IDs may come from tool results, from what the user typed, or from earlier
  // answers in this conversation (minus their own grounding notes, so an ID that
  // was flagged before doesn't become "verified" on the next turn).
  const priorAnswers = inputMessages
    .filter((m) => m.getType() === "ai")
    .map((m) => priorAnswerSource(messageText(m)));
  const sources = [
    ...finalMessages
      .filter((m) => m.getType() === "tool" || m.getType() === "human")
      .map((m) => (typeof m.content === "string" ? m.content : JSON.stringify(m.content))),
    ...priorAnswers,
  ];
  const ungrounded = findUngroundedIds(finalResponse, sources);
  if (ungrounded.length) console.log(`[chat] grounding check flagged: ${ungrounded.join(", ")}`);

  console.log(`[chat] answered in ${Date.now() - started}ms`);
  send({ type: "final", response: finalResponse + groundingNote(ungrounded), ungrounded });
}

